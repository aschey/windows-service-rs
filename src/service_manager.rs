use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::OsStringExt;
use std::{io, ptr};

use widestring::{U16CString, WideCString};
use windows_sys::Win32::System::Services::{self, ENUM_SERVICE_STATUSW};

use crate::sc_handle::ScHandle;
use crate::service::{to_wide, RawServiceInfo, Service, ServiceAccess, ServiceInfo, ServiceStatus};
use crate::{Error, Result};

bitflags::bitflags! {
    /// Flags describing access permissions for [`ServiceManager`].
    #[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Copy, Clone, Hash)]
    pub struct ServiceManagerAccess: u32 {
        /// Can connect to service control manager.
        const CONNECT = Services::SC_MANAGER_CONNECT;

        /// Can create services.
        const CREATE_SERVICE = Services::SC_MANAGER_CREATE_SERVICE;

        /// Can enumerate services or receive notifications.
        const ENUMERATE_SERVICE = Services::SC_MANAGER_ENUMERATE_SERVICE;

        /// Includes all possible access rights.
        const ALL_ACCESS = Services::SC_MANAGER_ALL_ACCESS;
    }
}

bitflags::bitflags! {
    pub struct ListServiceType: u32 {
        const DRIVER = Services::SERVICE_DRIVER;
        const FILE_SYSTEM_DRIVER = Services::SERVICE_FILE_SYSTEM_DRIVER;
        const KERNEL_DRIVER = Services::SERVICE_KERNEL_DRIVER;
        const WIN32 = Services::SERVICE_WIN32;
        const WIN32_OWN_PROCESS = Services::SERVICE_WIN32_OWN_PROCESS;
        const SHARE_PROCESS = Services::SERVICE_WIN32_SHARE_PROCESS;
    }
}

bitflags::bitflags! {
    pub struct ServiceActiveState: u32 {
        const ACTIVE = Services::SERVICE_ACTIVE;
        const INACTIVE = Services::SERVICE_INACTIVE;
        const ALL = Services::SERVICE_STATE_ALL;
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ServiceEntry {
    pub name: String,
    pub display_name: String,
    pub status: ServiceStatus,
}

impl ServiceEntry {
    fn from_raw(raw: ENUM_SERVICE_STATUSW) -> Result<Self> {
        unsafe {
            Ok(Self {
                name: U16CString::from_ptr_str(raw.lpServiceName).to_string_lossy(),
                display_name: U16CString::from_ptr_str(raw.lpDisplayName).to_string_lossy(),
                status: ServiceStatus::from_raw(raw.ServiceStatus)
                    .map_err(|e| Error::ParseValue("service_status", e))?,
            })
        }
    }
}

/// Service manager.
pub struct ServiceManager {
    manager_handle: ScHandle,
}

impl ServiceManager {
    /// Private initializer.
    ///
    /// # Arguments
    ///
    /// * `machine` - The name of machine. Pass `None` to connect to local machine.
    /// * `database` - The name of database to connect to. Pass `None` to connect to active
    ///   database.
    fn new(
        machine: Option<impl AsRef<OsStr>>,
        database: Option<impl AsRef<OsStr>>,
        request_access: ServiceManagerAccess,
    ) -> Result<Self> {
        let machine_name =
            to_wide(machine).map_err(|_| Error::ArgumentHasNulByte("machine name"))?;
        let database_name =
            to_wide(database).map_err(|_| Error::ArgumentHasNulByte("database name"))?;
        let handle = unsafe {
            Services::OpenSCManagerW(
                machine_name.map_or(ptr::null(), |s| s.as_ptr()),
                database_name.map_or(ptr::null(), |s| s.as_ptr()),
                request_access.bits(),
            )
        };

        if handle.is_null() {
            Err(Error::Winapi(io::Error::last_os_error()))
        } else {
            Ok(ServiceManager {
                manager_handle: unsafe { ScHandle::new(handle) },
            })
        }
    }

    /// Connect to local services database.
    ///
    /// # Arguments
    ///
    /// * `database` - The name of database to connect to. Pass `None` to connect to active
    ///   database.
    /// * `request_access` - Desired access permissions.
    pub fn local_computer(
        database: Option<impl AsRef<OsStr>>,
        request_access: ServiceManagerAccess,
    ) -> Result<Self> {
        ServiceManager::new(None::<&OsStr>, database, request_access)
    }

    /// Connect to remote services database.
    ///
    /// # Arguments
    ///
    /// * `machine` - The name of remote machine.
    /// * `database` - The name of database to connect to. Pass `None` to connect to active
    ///   database.
    /// * `request_access` - desired access permissions.
    pub fn remote_computer(
        machine: impl AsRef<OsStr>,
        database: Option<impl AsRef<OsStr>>,
        request_access: ServiceManagerAccess,
    ) -> Result<Self> {
        ServiceManager::new(Some(machine), database, request_access)
    }

    /// Create a service.
    ///
    /// # Arguments
    ///
    /// * `service_info` - The service information that will be saved to the system services
    ///   registry.
    /// * `service_access` - Desired access permissions for the returned [`Service`] instance.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use std::ffi::OsString;
    /// use std::path::PathBuf;
    /// use windows_service::service::{
    ///     ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceType,
    /// };
    /// use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    ///
    /// fn main() -> windows_service::Result<()> {
    ///     let manager =
    ///         ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE)?;
    ///
    ///     let my_service_info = ServiceInfo {
    ///         name: OsString::from("my_service"),
    ///         display_name: OsString::from("My service"),
    ///         service_type: ServiceType::OWN_PROCESS,
    ///         start_type: ServiceStartType::OnDemand,
    ///         error_control: ServiceErrorControl::Normal,
    ///         executable_path: PathBuf::from(r"C:\path\to\my\service.exe"),
    ///         launch_arguments: vec![],
    ///         dependencies: vec![],
    ///         account_name: None, // run as System
    ///         account_password: None,
    ///     };
    ///
    ///     let my_service = manager.create_service(&my_service_info, ServiceAccess::QUERY_STATUS)?;
    ///     Ok(())
    /// }
    /// ```
    pub fn create_service(
        &self,
        service_info: &ServiceInfo,
        service_access: ServiceAccess,
    ) -> Result<Service> {
        let service_name = WideCString::from_os_str(service_info.name.clone())
            .map_err(|_| Error::ArgumentHasNulByte("service_name"))?;

        let raw_info = RawServiceInfo::new(service_info)?;
        let service_handle = unsafe {
            Services::CreateServiceW(
                self.manager_handle.raw_handle(),
                raw_info.name.as_ptr(),
                raw_info.display_name.as_ptr(),
                service_access.bits(),
                raw_info.service_type,
                raw_info.start_type,
                raw_info.error_control,
                raw_info.launch_command.as_ptr(),
                ptr::null(),     // load ordering group
                ptr::null_mut(), // tag id within the load ordering group
                raw_info
                    .dependencies
                    .as_ref()
                    .map_or(ptr::null(), |s| s.as_ptr()),
                raw_info
                    .account_name
                    .as_ref()
                    .map_or(ptr::null(), |s| s.as_ptr()),
                raw_info
                    .account_password
                    .as_ref()
                    .map_or(ptr::null(), |s| s.as_ptr()),
            )
        };

        if service_handle.is_null() {
            Err(Error::Winapi(io::Error::last_os_error()))
        } else {
            Ok(Service::new(
                unsafe { ScHandle::new(service_handle) },
                service_name,
            ))
        }
    }

    /// Open an existing service.
    ///
    /// # Arguments
    ///
    /// * `name` - The service name.
    /// * `request_access` - Desired permissions for the returned [`Service`] instance.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use windows_service::service::ServiceAccess;
    /// use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    ///
    /// # fn main() -> windows_service::Result<()> {
    /// let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    /// let my_service = manager.open_service("my_service", ServiceAccess::QUERY_STATUS)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn open_service(
        &self,
        name: impl AsRef<OsStr>,
        request_access: ServiceAccess,
    ) -> Result<Service> {
        let service_name = WideCString::from_os_str(name)
            .map_err(|_| Error::ArgumentHasNulByte("service name"))?;
        let service_handle = unsafe {
            Services::OpenServiceW(
                self.manager_handle.raw_handle(),
                service_name.as_ptr(),
                request_access.bits(),
            )
        };

        if service_handle.is_null() {
            Err(Error::Winapi(io::Error::last_os_error()))
        } else {
            Ok(Service::new(
                unsafe { ScHandle::new(service_handle) },
                service_name,
            ))
        }
    }

    /// Return the service name given a service display name.
    ///
    /// # Arguments
    ///
    /// * `name` - A service display name.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    ///
    /// # fn main() -> windows_service::Result<()> {
    /// let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    /// let my_service_name = manager.service_name_from_display_name("My Service Display Name")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn service_name_from_display_name(
        &self,
        display_name: impl AsRef<OsStr>,
    ) -> Result<OsString> {
        let service_display_name = WideCString::from_os_str(display_name)
            .map_err(|_| Error::ArgumentHasNulByte("display name"))?;

        // As per docs, the maximum size of data buffer used by GetServiceKeyNameW is 4k bytes,
        // which is 2k wchars
        let mut buffer = [0u16; 2 * 1024];
        let mut buffer_len = u32::try_from(buffer.len()).expect("size must fit in u32");

        let result = unsafe {
            Services::GetServiceKeyNameW(
                self.manager_handle.raw_handle(),
                service_display_name.as_ptr(),
                buffer.as_mut_ptr(),
                &mut buffer_len,
            )
        };

        if result == 0 {
            Err(Error::Winapi(io::Error::last_os_error()))
        } else {
            Ok(OsString::from_wide(
                &buffer[..usize::try_from(buffer_len).unwrap()],
            ))
        }
    }

    pub fn get_all_services(
        &self,
        list_service_type: ListServiceType,
        service_active_state: ServiceActiveState,
    ) -> Result<Vec<ServiceEntry>> {
        const MAX_SERVICES: usize = 4096;
        let mut all_services = Vec::<ENUM_SERVICE_STATUSW>::with_capacity(MAX_SERVICES);
        let mut bytes_needed = 0u32;
        let mut num_services = 0u32;
        let mut resume_handle = 0u32;
        unsafe {
            let result = Services::EnumServicesStatusW(
                self.manager_handle.raw_handle(),
                list_service_type.bits(),
                service_active_state.bits(),
                all_services.as_mut_ptr(),
                (std::mem::size_of::<ENUM_SERVICE_STATUSW>() * MAX_SERVICES) as u32,
                &mut bytes_needed,
                &mut num_services,
                &mut resume_handle,
            );

            if result == 0 {
                return Err(Error::Winapi(io::Error::last_os_error()));
            }
            all_services.set_len(num_services as usize);
        };

        all_services
            .into_iter()
            .map(ServiceEntry::from_raw)
            .collect()
    }
}
