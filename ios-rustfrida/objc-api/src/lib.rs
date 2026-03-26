use common::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjcMethodInfo {
    pub class_name: String,
    pub selector_name: String,
    pub imp: usize,
    pub type_encoding: String,
    pub is_class_method: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjcMethodDetail {
    pub class_name: String,
    pub selector_name: String,
    pub method_pointer: usize,
    pub imp: usize,
    pub type_encoding: String,
    pub is_class_method: bool,
    pub image_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjcPropertyInfo {
    pub class_name: String,
    pub property_name: String,
    pub attributes: String,
    pub is_class_property: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjcPropertyDetail {
    pub class_name: String,
    pub property_name: String,
    pub attributes: String,
    pub is_class_property: bool,
    pub property_pointer: usize,
    pub image_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjcIvarInfo {
    pub class_name: String,
    pub ivar_name: String,
    pub type_encoding: String,
    pub offset: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjcIvarDetail {
    pub class_name: String,
    pub ivar_name: String,
    pub type_encoding: String,
    pub offset: usize,
    pub ivar_pointer: usize,
    pub image_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjcProtocolMethodInfo {
    pub protocol_name: String,
    pub selector_name: String,
    pub type_encoding: String,
    pub is_required: bool,
    pub is_instance_method: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjcProtocolMethodDetail {
    pub protocol_name: String,
    pub selector_name: String,
    pub type_encoding: String,
    pub is_required: bool,
    pub is_instance_method: bool,
    pub image_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjcProtocolPropertyInfo {
    pub protocol_name: String,
    pub property_name: String,
    pub attributes: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjcProtocolPropertyDetail {
    pub protocol_name: String,
    pub property_name: String,
    pub attributes: String,
    pub property_pointer: usize,
    pub image_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjcClassInfo {
    pub class_name: String,
    pub class_pointer: usize,
    pub is_meta_class: bool,
    pub superclass_name: Option<String>,
    pub superclass_pointer: Option<usize>,
    pub instance_size: usize,
    pub image_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjcProtocolInfo {
    pub protocol_name: String,
    pub protocol_pointer: usize,
    pub adopted_protocols: Vec<String>,
    pub required_instance_method_count: usize,
    pub required_class_method_count: usize,
    pub optional_instance_method_count: usize,
    pub optional_class_method_count: usize,
    pub property_count: usize,
    pub image_path: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ObjcApi;

impl Default for ObjcApi {
    fn default() -> Self {
        Self::new()
    }
}

impl ObjcApi {
    pub fn new() -> Self {
        Self
    }

    pub fn is_available(&self) -> bool {
        cfg!(any(target_os = "ios", target_os = "macos"))
    }

    pub fn class_exists(&self, name: &str) -> bool {
        platform::class_exists(name)
    }

    pub fn enumerate_classes(&self) -> Result<Vec<String>> {
        platform::enumerate_classes()
    }

    pub fn find_classes(&self, query: &str) -> Result<Vec<String>> {
        platform::find_classes(query)
    }

    pub fn selector(&self, name: &str) -> Result<usize> {
        platform::selector(name)
    }

    pub fn enumerate_protocols(&self) -> Result<Vec<String>> {
        platform::enumerate_protocols()
    }

    pub fn find_protocols(&self, query: &str) -> Result<Vec<String>> {
        platform::find_protocols(query)
    }

    pub fn class_protocols(&self, class_name: &str) -> Result<Vec<String>> {
        platform::class_protocols(class_name)
    }

    pub fn superclass(&self, class_name: &str) -> Result<Option<String>> {
        platform::superclass(class_name)
    }

    pub fn class_chain(&self, class_name: &str) -> Result<Vec<String>> {
        platform::class_chain(class_name)
    }

    pub fn class_info(&self, class_name: &str, is_meta_class: bool) -> Result<Option<ObjcClassInfo>> {
        platform::class_info(class_name, is_meta_class)
    }

    pub fn protocol_info(&self, protocol_name: &str) -> Result<Option<ObjcProtocolInfo>> {
        platform::protocol_info(protocol_name)
    }

    pub fn protocol_methods(
        &self,
        protocol_name: &str,
        is_required: bool,
        is_instance_method: bool,
    ) -> Result<Vec<ObjcProtocolMethodInfo>> {
        platform::protocol_methods(protocol_name, is_required, is_instance_method)
    }

    pub fn protocol_method_info(
        &self,
        protocol_name: &str,
        selector_name: &str,
        is_required: bool,
        is_instance_method: bool,
    ) -> Result<Option<ObjcProtocolMethodDetail>> {
        platform::protocol_method_info(protocol_name, selector_name, is_required, is_instance_method)
    }

    pub fn protocol_properties(&self, protocol_name: &str) -> Result<Vec<ObjcProtocolPropertyInfo>> {
        platform::protocol_properties(protocol_name)
    }

    pub fn protocol_property_info(
        &self,
        protocol_name: &str,
        property_name: &str,
    ) -> Result<Option<ObjcProtocolPropertyDetail>> {
        platform::protocol_property_info(protocol_name, property_name)
    }

    pub fn protocol_protocols(&self, protocol_name: &str) -> Result<Vec<String>> {
        platform::protocol_protocols(protocol_name)
    }

    pub fn enumerate_properties(&self, class_name: &str, is_class_property: bool) -> Result<Vec<ObjcPropertyInfo>> {
        platform::enumerate_properties(class_name, is_class_property)
    }

    pub fn property_info(
        &self,
        class_name: &str,
        property_name: &str,
        is_class_property: bool,
    ) -> Result<Option<ObjcPropertyDetail>> {
        platform::property_info(class_name, property_name, is_class_property)
    }

    pub fn find_properties(
        &self,
        class_name: &str,
        query: &str,
        is_class_property: bool,
    ) -> Result<Vec<ObjcPropertyInfo>> {
        platform::find_properties(class_name, query, is_class_property)
    }

    pub fn enumerate_ivars(&self, class_name: &str) -> Result<Vec<ObjcIvarInfo>> {
        platform::enumerate_ivars(class_name)
    }

    pub fn ivar_info(&self, class_name: &str, ivar_name: &str) -> Result<Option<ObjcIvarDetail>> {
        platform::ivar_info(class_name, ivar_name)
    }

    pub fn find_ivars(&self, class_name: &str, query: &str) -> Result<Vec<ObjcIvarInfo>> {
        platform::find_ivars(class_name, query)
    }

    pub fn method_imp(&self, class_name: &str, selector_name: &str, is_class_method: bool) -> Result<Option<usize>> {
        platform::method_imp(class_name, selector_name, is_class_method)
    }

    pub fn method_info(
        &self,
        class_name: &str,
        selector_name: &str,
        is_class_method: bool,
    ) -> Result<Option<ObjcMethodDetail>> {
        platform::method_info(class_name, selector_name, is_class_method)
    }

    pub fn enumerate_methods(&self, class_name: &str, is_class_method: bool) -> Result<Vec<ObjcMethodInfo>> {
        platform::enumerate_methods(class_name, is_class_method)
    }

    pub fn find_methods(&self, class_name: &str, query: &str, is_class_method: bool) -> Result<Vec<ObjcMethodInfo>> {
        platform::find_methods(class_name, query, is_class_method)
    }

    pub fn find_method_owners(&self, query: &str, is_class_method: bool) -> Result<Vec<ObjcMethodInfo>> {
        platform::find_method_owners(query, is_class_method)
    }

    pub fn class_image(&self, class_name: &str) -> Result<Option<String>> {
        platform::class_image(class_name)
    }

    pub fn method_image(&self, class_name: &str, selector_name: &str, is_class_method: bool) -> Result<Option<String>> {
        platform::method_image(class_name, selector_name, is_class_method)
    }

    pub fn selector_name(&self, selector: usize) -> Result<Option<String>> {
        platform::selector_name(selector)
    }

    pub fn object_class_name(&self, object: usize) -> Result<Option<String>> {
        platform::object_class_name(object)
    }
}

#[cfg_attr(not(any(target_os = "ios", target_os = "macos")), allow(dead_code))]
fn query_matches_class_name(class_name: &str, query: &str) -> bool {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return false;
    }

    class_name.to_ascii_lowercase().contains(&trimmed.to_ascii_lowercase())
}

#[cfg_attr(not(any(target_os = "ios", target_os = "macos")), allow(dead_code))]
fn query_matches_method_name(selector_name: &str, query: &str) -> bool {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return false;
    }

    selector_name
        .to_ascii_lowercase()
        .contains(&trimmed.to_ascii_lowercase())
}

#[cfg_attr(not(any(target_os = "ios", target_os = "macos")), allow(dead_code))]
fn query_matches_property_name(property_name: &str, query: &str) -> bool {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return false;
    }

    property_name
        .to_ascii_lowercase()
        .contains(&trimmed.to_ascii_lowercase())
}

#[cfg_attr(not(any(target_os = "ios", target_os = "macos")), allow(dead_code))]
fn query_matches_ivar_name(ivar_name: &str, query: &str) -> bool {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return false;
    }

    ivar_name.to_ascii_lowercase().contains(&trimmed.to_ascii_lowercase())
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
mod platform {
    use std::ffi::{CStr, CString};
    use std::os::raw::{c_char, c_void};

    use common::{Error, Result};

    use crate::{
        query_matches_class_name, query_matches_ivar_name, query_matches_method_name, query_matches_property_name,
        ObjcClassInfo, ObjcIvarDetail, ObjcIvarInfo, ObjcMethodDetail, ObjcMethodInfo, ObjcPropertyDetail,
        ObjcPropertyInfo, ObjcProtocolInfo, ObjcProtocolMethodDetail, ObjcProtocolMethodInfo,
        ObjcProtocolPropertyDetail, ObjcProtocolPropertyInfo,
    };

    #[link(name = "objc")]
    extern "C" {
        fn objc_getClass(name: *const c_char) -> *mut c_void;
        fn objc_getProtocol(name: *const c_char) -> *mut c_void;
        fn objc_copyProtocolList(out_count: *mut u32) -> *mut *mut c_void;
        fn class_copyProtocolList(cls: *const c_void, out_count: *mut u32) -> *mut *mut c_void;
        fn class_copyPropertyList(cls: *const c_void, out_count: *mut u32) -> *mut *mut c_void;
        fn class_copyIvarList(cls: *const c_void, out_count: *mut u32) -> *mut *mut c_void;
        fn protocol_copyMethodDescriptionList(
            proto: *const c_void,
            is_required_method: i8,
            is_instance_method: i8,
            out_count: *mut u32,
        ) -> *mut ObjcMethodDescription;
        fn protocol_copyPropertyList(proto: *const c_void, out_count: *mut u32) -> *mut *mut c_void;
        fn protocol_copyProtocolList(proto: *const c_void, out_count: *mut u32) -> *mut *mut c_void;
        fn object_getClass(obj: *const c_void) -> *mut c_void;
        fn objc_copyClassList(out_count: *mut u32) -> *mut *mut c_void;
        fn class_copyMethodList(cls: *const c_void, out_count: *mut u32) -> *mut *mut c_void;
        fn class_getName(cls: *const c_void) -> *const c_char;
        fn class_getSuperclass(cls: *const c_void) -> *mut c_void;
        fn class_getInstanceSize(cls: *const c_void) -> usize;
        fn class_isMetaClass(cls: *const c_void) -> i8;
        fn protocol_getName(proto: *const c_void) -> *const c_char;
        fn property_getName(property: *const c_void) -> *const c_char;
        fn property_getAttributes(property: *const c_void) -> *const c_char;
        fn ivar_getName(ivar: *const c_void) -> *const c_char;
        fn ivar_getTypeEncoding(ivar: *const c_void) -> *const c_char;
        fn ivar_getOffset(ivar: *const c_void) -> isize;
        fn class_getInstanceMethod(cls: *const c_void, sel: *const c_void) -> *mut c_void;
        fn class_getClassMethod(cls: *const c_void, sel: *const c_void) -> *mut c_void;
        fn method_getName(method: *const c_void) -> *const c_void;
        fn method_getImplementation(method: *const c_void) -> *const c_void;
        fn method_getTypeEncoding(method: *const c_void) -> *const c_char;
        fn sel_registerName(name: *const c_char) -> *const c_void;
        fn sel_getName(sel: *const c_void) -> *const c_char;
        fn dladdr(addr: *const c_void, info: *mut DlInfo) -> i32;
    }

    #[repr(C)]
    struct DlInfo {
        dli_fname: *const c_char,
        dli_fbase: *mut c_void,
        dli_sname: *const c_char,
        dli_saddr: *mut c_void,
    }

    #[repr(C)]
    struct ObjcMethodDescription {
        name: *const c_void,
        types: *const c_char,
    }

    struct ResolvedMethod {
        method_pointer: usize,
        imp: usize,
        type_encoding: String,
    }

    struct ResolvedProperty {
        property_pointer: usize,
        attributes: String,
        image_path: Option<String>,
    }

    pub fn class_exists(name: &str) -> bool {
        let Ok(name) = CString::new(name) else {
            return false;
        };
        unsafe { !objc_getClass(name.as_ptr()).is_null() }
    }

    pub fn enumerate_classes() -> Result<Vec<String>> {
        let mut count = 0u32;
        let list = unsafe { objc_copyClassList(&mut count as *mut u32) };
        if list.is_null() {
            return Ok(Vec::new());
        }

        let slice = unsafe { std::slice::from_raw_parts(list, count as usize) };
        let mut classes = Vec::with_capacity(slice.len());
        for cls in slice {
            let name = unsafe { class_getName(*cls as *const c_void) };
            if name.is_null() {
                continue;
            }
            classes.push(unsafe { CStr::from_ptr(name) }.to_string_lossy().into_owned());
        }
        unsafe { libc::free(list.cast()) };
        classes.sort();
        Ok(classes)
    }

    pub fn find_classes(query: &str) -> Result<Vec<String>> {
        let trimmed = query.trim();
        if trimmed.is_empty() {
            return Err(Error::InvalidArgument("class query must not be empty".into()));
        }

        let mut classes = enumerate_classes()?;
        classes.retain(|name| query_matches_class_name(name, trimmed));
        Ok(classes)
    }

    pub fn selector(name: &str) -> Result<usize> {
        let name = CString::new(name).map_err(|_| Error::InvalidArgument("selector contains interior NUL".into()))?;
        let ptr = unsafe { sel_registerName(name.as_ptr()) };
        Ok(ptr as usize)
    }

    pub fn enumerate_protocols() -> Result<Vec<String>> {
        let mut count = 0u32;
        let list = unsafe { objc_copyProtocolList(&mut count as *mut u32) };
        if list.is_null() {
            return Ok(Vec::new());
        }

        let slice = unsafe { std::slice::from_raw_parts(list, count as usize) };
        let mut protocols = Vec::with_capacity(slice.len());
        for proto in slice {
            if proto.is_null() {
                continue;
            }

            let name = unsafe { protocol_getName(*proto as *const c_void) };
            if name.is_null() {
                continue;
            }

            protocols.push(unsafe { CStr::from_ptr(name) }.to_string_lossy().into_owned());
        }

        unsafe { libc::free(list.cast()) };
        protocols.sort();
        protocols.dedup();
        Ok(protocols)
    }

    pub fn find_protocols(query: &str) -> Result<Vec<String>> {
        let trimmed = query.trim();
        if trimmed.is_empty() {
            return Err(Error::InvalidArgument("protocol query must not be empty".into()));
        }

        let mut protocols = enumerate_protocols()?;
        protocols.retain(|name| query_matches_class_name(name, trimmed));
        Ok(protocols)
    }

    pub fn class_protocols(class_name: &str) -> Result<Vec<String>> {
        let class_name = class_name.trim();
        if class_name.is_empty() {
            return Err(Error::InvalidArgument("class name must not be empty".into()));
        }

        let class_name_c =
            CString::new(class_name).map_err(|_| Error::InvalidArgument("class name contains interior NUL".into()))?;
        let class = unsafe { objc_getClass(class_name_c.as_ptr()) };
        if class.is_null() {
            return Ok(Vec::new());
        }

        let mut count = 0u32;
        let list = unsafe { class_copyProtocolList(class, &mut count as *mut u32) };
        if list.is_null() {
            return Ok(Vec::new());
        }

        let slice = unsafe { std::slice::from_raw_parts(list, count as usize) };
        let mut protocols = Vec::with_capacity(slice.len());
        for proto in slice {
            if proto.is_null() {
                continue;
            }

            let name = unsafe { protocol_getName(*proto as *const c_void) };
            if name.is_null() {
                continue;
            }

            protocols.push(unsafe { CStr::from_ptr(name) }.to_string_lossy().into_owned());
        }

        unsafe { libc::free(list.cast()) };
        protocols.sort();
        protocols.dedup();
        Ok(protocols)
    }

    pub fn superclass(class_name: &str) -> Result<Option<String>> {
        let class_name = class_name.trim();
        if class_name.is_empty() {
            return Err(Error::InvalidArgument("class name must not be empty".into()));
        }

        let class_name_c =
            CString::new(class_name).map_err(|_| Error::InvalidArgument("class name contains interior NUL".into()))?;
        let class = unsafe { objc_getClass(class_name_c.as_ptr()) };
        if class.is_null() {
            return Ok(None);
        }

        let superclass = unsafe { class_getSuperclass(class) };
        if superclass.is_null() {
            return Ok(None);
        }

        let name = unsafe { class_getName(superclass as *const c_void) };
        if name.is_null() {
            return Ok(None);
        }

        Ok(Some(unsafe { CStr::from_ptr(name) }.to_string_lossy().into_owned()))
    }

    pub fn class_chain(class_name: &str) -> Result<Vec<String>> {
        let class_name = class_name.trim();
        if class_name.is_empty() {
            return Err(Error::InvalidArgument("class name must not be empty".into()));
        }

        let class_name_c =
            CString::new(class_name).map_err(|_| Error::InvalidArgument("class name contains interior NUL".into()))?;
        let mut class = unsafe { objc_getClass(class_name_c.as_ptr()) };
        if class.is_null() {
            return Ok(Vec::new());
        }

        let mut chain = Vec::new();
        while !class.is_null() {
            let name = unsafe { class_getName(class as *const c_void) };
            if name.is_null() {
                break;
            }

            chain.push(unsafe { CStr::from_ptr(name) }.to_string_lossy().into_owned());
            class = unsafe { class_getSuperclass(class as *const c_void) };
        }

        Ok(chain)
    }

    pub fn class_info(class_name: &str, is_meta_class: bool) -> Result<Option<ObjcClassInfo>> {
        let class_name = class_name.trim();
        if class_name.is_empty() {
            return Err(Error::InvalidArgument("class name must not be empty".into()));
        }

        let class_name_c =
            CString::new(class_name).map_err(|_| Error::InvalidArgument("class name contains interior NUL".into()))?;
        let class = unsafe { objc_getClass(class_name_c.as_ptr()) };
        if class.is_null() {
            return Ok(None);
        }

        let lookup_class = if is_meta_class {
            unsafe { object_getClass(class) }
        } else {
            class
        };
        if lookup_class.is_null() {
            return Ok(None);
        }

        let resolved_name = unsafe { class_getName(lookup_class as *const c_void) };
        if resolved_name.is_null() {
            return Ok(None);
        }

        let superclass = unsafe { class_getSuperclass(lookup_class as *const c_void) };
        let superclass_name = if superclass.is_null() {
            None
        } else {
            let name = unsafe { class_getName(superclass as *const c_void) };
            if name.is_null() {
                None
            } else {
                Some(unsafe { CStr::from_ptr(name) }.to_string_lossy().into_owned())
            }
        };
        let image_path = image_path_for_address(lookup_class as *const c_void)?;

        Ok(Some(ObjcClassInfo {
            class_name: unsafe { CStr::from_ptr(resolved_name) }.to_string_lossy().into_owned(),
            class_pointer: lookup_class as usize,
            is_meta_class: unsafe { class_isMetaClass(lookup_class as *const c_void) != 0 },
            superclass_name,
            superclass_pointer: if superclass.is_null() {
                None
            } else {
                Some(superclass as usize)
            },
            instance_size: unsafe { class_getInstanceSize(lookup_class as *const c_void) },
            image_path,
        }))
    }

    pub fn protocol_info(protocol_name: &str) -> Result<Option<ObjcProtocolInfo>> {
        let protocol_name = protocol_name.trim();
        if protocol_name.is_empty() {
            return Err(Error::InvalidArgument("protocol name must not be empty".into()));
        }

        let protocol_name_c = CString::new(protocol_name)
            .map_err(|_| Error::InvalidArgument("protocol name contains interior NUL".into()))?;
        let protocol = unsafe { objc_getProtocol(protocol_name_c.as_ptr()) };
        if protocol.is_null() {
            return Ok(None);
        }

        let resolved_name = unsafe { protocol_getName(protocol as *const c_void) };
        if resolved_name.is_null() {
            return Ok(None);
        }

        let adopted_protocols = protocol_protocols(protocol_name)?;
        let required_instance_method_count = protocol_methods(protocol_name, true, true)?.len();
        let required_class_method_count = protocol_methods(protocol_name, true, false)?.len();
        let optional_instance_method_count = protocol_methods(protocol_name, false, true)?.len();
        let optional_class_method_count = protocol_methods(protocol_name, false, false)?.len();
        let property_count = protocol_properties(protocol_name)?.len();
        let image_path = image_path_for_address(protocol as *const c_void)?;

        Ok(Some(ObjcProtocolInfo {
            protocol_name: unsafe { CStr::from_ptr(resolved_name) }.to_string_lossy().into_owned(),
            protocol_pointer: protocol as usize,
            adopted_protocols,
            required_instance_method_count,
            required_class_method_count,
            optional_instance_method_count,
            optional_class_method_count,
            property_count,
            image_path,
        }))
    }

    pub fn protocol_methods(
        protocol_name: &str,
        is_required: bool,
        is_instance_method: bool,
    ) -> Result<Vec<ObjcProtocolMethodInfo>> {
        let protocol_name = protocol_name.trim();
        if protocol_name.is_empty() {
            return Err(Error::InvalidArgument("protocol name must not be empty".into()));
        }

        let protocol_name_c = CString::new(protocol_name)
            .map_err(|_| Error::InvalidArgument("protocol name contains interior NUL".into()))?;
        let protocol = unsafe { objc_getProtocol(protocol_name_c.as_ptr()) };
        if protocol.is_null() {
            return Ok(Vec::new());
        }

        let mut count = 0u32;
        let list = unsafe {
            protocol_copyMethodDescriptionList(
                protocol,
                if is_required { 1 } else { 0 },
                if is_instance_method { 1 } else { 0 },
                &mut count as *mut u32,
            )
        };
        if list.is_null() {
            return Ok(Vec::new());
        }

        let slice = unsafe { std::slice::from_raw_parts(list, count as usize) };
        let mut methods = Vec::with_capacity(slice.len());
        for method in slice {
            if method.name.is_null() {
                continue;
            }

            let selector_name = unsafe { sel_getName(method.name) };
            if selector_name.is_null() {
                continue;
            }

            methods.push(ObjcProtocolMethodInfo {
                protocol_name: protocol_name.to_string(),
                selector_name: unsafe { CStr::from_ptr(selector_name) }.to_string_lossy().into_owned(),
                type_encoding: if method.types.is_null() {
                    String::new()
                } else {
                    unsafe { CStr::from_ptr(method.types) }.to_string_lossy().into_owned()
                },
                is_required,
                is_instance_method,
            });
        }

        unsafe { libc::free(list.cast()) };
        methods.sort_by(|left, right| {
            left.selector_name
                .cmp(&right.selector_name)
                .then(left.type_encoding.cmp(&right.type_encoding))
        });
        methods.dedup_by(|left, right| {
            left.selector_name == right.selector_name
                && left.type_encoding == right.type_encoding
                && left.is_required == right.is_required
                && left.is_instance_method == right.is_instance_method
        });
        Ok(methods)
    }

    pub fn protocol_method_info(
        protocol_name: &str,
        selector_name: &str,
        is_required: bool,
        is_instance_method: bool,
    ) -> Result<Option<ObjcProtocolMethodDetail>> {
        let protocol_name = protocol_name.trim();
        if protocol_name.is_empty() {
            return Err(Error::InvalidArgument("protocol name must not be empty".into()));
        }

        let selector_name = selector_name.trim();
        if selector_name.is_empty() {
            return Err(Error::InvalidArgument("selector name must not be empty".into()));
        }

        let protocol_name_c = CString::new(protocol_name)
            .map_err(|_| Error::InvalidArgument("protocol name contains interior NUL".into()))?;
        let protocol = unsafe { objc_getProtocol(protocol_name_c.as_ptr()) };
        if protocol.is_null() {
            return Ok(None);
        }

        let mut count = 0u32;
        let list = unsafe {
            protocol_copyMethodDescriptionList(protocol, is_required as i8, is_instance_method as i8, &mut count)
        };
        if list.is_null() {
            return Ok(None);
        }

        let slice = unsafe { std::slice::from_raw_parts(list, count as usize) };
        let mut resolved = None;
        for method in slice {
            if method.name.is_null() {
                continue;
            }

            let resolved_selector_name = unsafe { sel_getName(method.name) };
            if resolved_selector_name.is_null() {
                continue;
            }
            let resolved_selector_name = unsafe { CStr::from_ptr(resolved_selector_name) }.to_string_lossy();
            if resolved_selector_name.as_ref() != selector_name {
                continue;
            }

            resolved = Some(ObjcProtocolMethodDetail {
                protocol_name: protocol_name.to_string(),
                selector_name: selector_name.to_string(),
                type_encoding: if method.types.is_null() {
                    String::new()
                } else {
                    unsafe { CStr::from_ptr(method.types) }.to_string_lossy().into_owned()
                },
                is_required,
                is_instance_method,
                image_path: image_path_for_address(protocol as *const c_void)?,
            });
            break;
        }

        unsafe { libc::free(list.cast()) };
        Ok(resolved)
    }

    pub fn protocol_properties(protocol_name: &str) -> Result<Vec<ObjcProtocolPropertyInfo>> {
        let protocol_name = protocol_name.trim();
        if protocol_name.is_empty() {
            return Err(Error::InvalidArgument("protocol name must not be empty".into()));
        }

        let protocol_name_c = CString::new(protocol_name)
            .map_err(|_| Error::InvalidArgument("protocol name contains interior NUL".into()))?;
        let protocol = unsafe { objc_getProtocol(protocol_name_c.as_ptr()) };
        if protocol.is_null() {
            return Ok(Vec::new());
        }

        let mut count = 0u32;
        let list = unsafe { protocol_copyPropertyList(protocol, &mut count as *mut u32) };
        if list.is_null() {
            return Ok(Vec::new());
        }

        let slice = unsafe { std::slice::from_raw_parts(list, count as usize) };
        let mut properties = Vec::with_capacity(slice.len());
        for property in slice {
            if property.is_null() {
                continue;
            }

            let name = unsafe { property_getName(*property as *const c_void) };
            if name.is_null() {
                continue;
            }

            let attributes = unsafe { property_getAttributes(*property as *const c_void) };
            properties.push(ObjcProtocolPropertyInfo {
                protocol_name: protocol_name.to_string(),
                property_name: unsafe { CStr::from_ptr(name) }.to_string_lossy().into_owned(),
                attributes: if attributes.is_null() {
                    String::new()
                } else {
                    unsafe { CStr::from_ptr(attributes) }.to_string_lossy().into_owned()
                },
            });
        }

        unsafe { libc::free(list.cast()) };
        properties.sort_by(|left, right| left.property_name.cmp(&right.property_name));
        properties
            .dedup_by(|left, right| left.property_name == right.property_name && left.attributes == right.attributes);
        Ok(properties)
    }

    pub fn protocol_property_info(
        protocol_name: &str,
        property_name: &str,
    ) -> Result<Option<ObjcProtocolPropertyDetail>> {
        let protocol_name = protocol_name.trim();
        if protocol_name.is_empty() {
            return Err(Error::InvalidArgument("protocol name must not be empty".into()));
        }

        let property_name = property_name.trim();
        if property_name.is_empty() {
            return Err(Error::InvalidArgument("property name must not be empty".into()));
        }

        let protocol_name_c = CString::new(protocol_name)
            .map_err(|_| Error::InvalidArgument("protocol name contains interior NUL".into()))?;
        let protocol = unsafe { objc_getProtocol(protocol_name_c.as_ptr()) };
        if protocol.is_null() {
            return Ok(None);
        }

        let mut count = 0u32;
        let list = unsafe { protocol_copyPropertyList(protocol, &mut count as *mut u32) };
        if list.is_null() {
            return Ok(None);
        }

        let slice = unsafe { std::slice::from_raw_parts(list, count as usize) };
        let mut resolved = None;
        for property in slice {
            if property.is_null() {
                continue;
            }

            let name = unsafe { property_getName(*property as *const c_void) };
            if name.is_null() {
                continue;
            }
            let resolved_name = unsafe { CStr::from_ptr(name) }.to_string_lossy();
            if resolved_name.as_ref() != property_name {
                continue;
            }

            let attributes = unsafe { property_getAttributes(*property as *const c_void) };
            resolved = Some(ObjcProtocolPropertyDetail {
                protocol_name: protocol_name.to_string(),
                property_name: property_name.to_string(),
                attributes: if attributes.is_null() {
                    String::new()
                } else {
                    unsafe { CStr::from_ptr(attributes) }.to_string_lossy().into_owned()
                },
                property_pointer: *property as usize,
                image_path: image_path_for_address(protocol as *const c_void)?,
            });
            break;
        }

        unsafe { libc::free(list.cast()) };
        Ok(resolved)
    }

    pub fn protocol_protocols(protocol_name: &str) -> Result<Vec<String>> {
        let protocol_name = protocol_name.trim();
        if protocol_name.is_empty() {
            return Err(Error::InvalidArgument("protocol name must not be empty".into()));
        }

        let protocol_name_c = CString::new(protocol_name)
            .map_err(|_| Error::InvalidArgument("protocol name contains interior NUL".into()))?;
        let protocol = unsafe { objc_getProtocol(protocol_name_c.as_ptr()) };
        if protocol.is_null() {
            return Ok(Vec::new());
        }

        let mut count = 0u32;
        let list = unsafe { protocol_copyProtocolList(protocol, &mut count as *mut u32) };
        if list.is_null() {
            return Ok(Vec::new());
        }

        let slice = unsafe { std::slice::from_raw_parts(list, count as usize) };
        let mut protocols = Vec::with_capacity(slice.len());
        for adopted_protocol in slice {
            if adopted_protocol.is_null() {
                continue;
            }

            let name = unsafe { protocol_getName(*adopted_protocol as *const c_void) };
            if name.is_null() {
                continue;
            }

            protocols.push(unsafe { CStr::from_ptr(name) }.to_string_lossy().into_owned());
        }

        unsafe { libc::free(list.cast()) };
        protocols.sort();
        protocols.dedup();
        Ok(protocols)
    }

    pub fn enumerate_properties(class_name: &str, is_class_property: bool) -> Result<Vec<ObjcPropertyInfo>> {
        let class_name = class_name.trim();
        if class_name.is_empty() {
            return Err(Error::InvalidArgument("class name must not be empty".into()));
        }

        let class_name_c =
            CString::new(class_name).map_err(|_| Error::InvalidArgument("class name contains interior NUL".into()))?;
        let class = unsafe { objc_getClass(class_name_c.as_ptr()) };
        if class.is_null() {
            return Ok(Vec::new());
        }

        let lookup_class = if is_class_property {
            unsafe { object_getClass(class) }
        } else {
            class
        };
        if lookup_class.is_null() {
            return Ok(Vec::new());
        }

        let mut count = 0u32;
        let list = unsafe { class_copyPropertyList(lookup_class, &mut count as *mut u32) };
        if list.is_null() {
            return Ok(Vec::new());
        }

        let slice = unsafe { std::slice::from_raw_parts(list, count as usize) };
        let mut properties = Vec::with_capacity(slice.len());
        for property in slice {
            if property.is_null() {
                continue;
            }

            let name = unsafe { property_getName(*property as *const c_void) };
            if name.is_null() {
                continue;
            }

            let attributes = unsafe { property_getAttributes(*property as *const c_void) };
            properties.push(ObjcPropertyInfo {
                class_name: class_name.to_string(),
                property_name: unsafe { CStr::from_ptr(name) }.to_string_lossy().into_owned(),
                attributes: if attributes.is_null() {
                    String::new()
                } else {
                    unsafe { CStr::from_ptr(attributes) }.to_string_lossy().into_owned()
                },
                is_class_property,
            });
        }

        unsafe { libc::free(list.cast()) };
        properties.sort_by(|left, right| left.property_name.cmp(&right.property_name));
        properties.dedup_by(|left, right| {
            left.property_name == right.property_name
                && left.attributes == right.attributes
                && left.is_class_property == right.is_class_property
        });
        Ok(properties)
    }

    fn resolve_property(
        class_name: &str,
        property_name: &str,
        is_class_property: bool,
    ) -> Result<Option<ResolvedProperty>> {
        let class_name = class_name.trim();
        if class_name.is_empty() {
            return Err(Error::InvalidArgument("class name must not be empty".into()));
        }

        let property_name = property_name.trim();
        if property_name.is_empty() {
            return Err(Error::InvalidArgument("property name must not be empty".into()));
        }

        let class_name_c =
            CString::new(class_name).map_err(|_| Error::InvalidArgument("class name contains interior NUL".into()))?;
        let class = unsafe { objc_getClass(class_name_c.as_ptr()) };
        if class.is_null() {
            return Ok(None);
        }

        let lookup_class = if is_class_property {
            unsafe { object_getClass(class) }
        } else {
            class
        };
        if lookup_class.is_null() {
            return Ok(None);
        }

        let mut count = 0u32;
        let list = unsafe { class_copyPropertyList(lookup_class, &mut count as *mut u32) };
        if list.is_null() {
            return Ok(None);
        }

        let slice = unsafe { std::slice::from_raw_parts(list, count as usize) };
        let mut resolved = None;
        for property in slice {
            if property.is_null() {
                continue;
            }

            let name = unsafe { property_getName(*property as *const c_void) };
            if name.is_null() {
                continue;
            }
            let resolved_name = unsafe { CStr::from_ptr(name) }.to_string_lossy();
            if resolved_name.as_ref() != property_name {
                continue;
            }

            let attributes = unsafe { property_getAttributes(*property as *const c_void) };
            resolved = Some(ResolvedProperty {
                property_pointer: *property as usize,
                attributes: if attributes.is_null() {
                    String::new()
                } else {
                    unsafe { CStr::from_ptr(attributes) }.to_string_lossy().into_owned()
                },
                image_path: image_path_for_address(lookup_class as *const c_void)?,
            });
            break;
        }

        unsafe { libc::free(list.cast()) };
        Ok(resolved)
    }

    pub fn property_info(
        class_name: &str,
        property_name: &str,
        is_class_property: bool,
    ) -> Result<Option<ObjcPropertyDetail>> {
        let Some(property) = resolve_property(class_name, property_name, is_class_property)? else {
            return Ok(None);
        };

        Ok(Some(ObjcPropertyDetail {
            class_name: class_name.trim().to_string(),
            property_name: property_name.trim().to_string(),
            attributes: property.attributes,
            is_class_property,
            property_pointer: property.property_pointer,
            image_path: property.image_path,
        }))
    }

    pub fn find_properties(class_name: &str, query: &str, is_class_property: bool) -> Result<Vec<ObjcPropertyInfo>> {
        let trimmed = query.trim();
        if trimmed.is_empty() {
            return Err(Error::InvalidArgument("property query must not be empty".into()));
        }

        let mut properties = enumerate_properties(class_name, is_class_property)?;
        properties.retain(|property| query_matches_property_name(&property.property_name, trimmed));
        Ok(properties)
    }

    pub fn ivar_info(class_name: &str, ivar_name: &str) -> Result<Option<ObjcIvarDetail>> {
        let class_name = class_name.trim();
        if class_name.is_empty() {
            return Err(Error::InvalidArgument("class name must not be empty".into()));
        }

        let ivar_name = ivar_name.trim();
        if ivar_name.is_empty() {
            return Err(Error::InvalidArgument("ivar name must not be empty".into()));
        }

        let class_name_c =
            CString::new(class_name).map_err(|_| Error::InvalidArgument("class name contains interior NUL".into()))?;
        let class = unsafe { objc_getClass(class_name_c.as_ptr()) };
        if class.is_null() {
            return Ok(None);
        }

        let mut count = 0u32;
        let list = unsafe { class_copyIvarList(class, &mut count as *mut u32) };
        if list.is_null() {
            return Ok(None);
        }

        let slice = unsafe { std::slice::from_raw_parts(list, count as usize) };
        let mut resolved = None;
        for ivar in slice {
            if ivar.is_null() {
                continue;
            }

            let name = unsafe { ivar_getName(*ivar as *const c_void) };
            if name.is_null() {
                continue;
            }
            let resolved_name = unsafe { CStr::from_ptr(name) }.to_string_lossy();
            if resolved_name.as_ref() != ivar_name {
                continue;
            }

            let type_encoding = unsafe { ivar_getTypeEncoding(*ivar as *const c_void) };
            let offset = unsafe { ivar_getOffset(*ivar as *const c_void) };
            if offset < 0 {
                continue;
            }
            resolved = Some(ObjcIvarDetail {
                class_name: class_name.to_string(),
                ivar_name: ivar_name.to_string(),
                type_encoding: if type_encoding.is_null() {
                    String::new()
                } else {
                    unsafe { CStr::from_ptr(type_encoding) }.to_string_lossy().into_owned()
                },
                offset: offset as usize,
                ivar_pointer: *ivar as usize,
                image_path: image_path_for_address(class as *const c_void)?,
            });
            break;
        }

        unsafe { libc::free(list.cast()) };
        Ok(resolved)
    }

    pub fn enumerate_ivars(class_name: &str) -> Result<Vec<ObjcIvarInfo>> {
        let class_name = class_name.trim();
        if class_name.is_empty() {
            return Err(Error::InvalidArgument("class name must not be empty".into()));
        }

        let class_name_c =
            CString::new(class_name).map_err(|_| Error::InvalidArgument("class name contains interior NUL".into()))?;
        let class = unsafe { objc_getClass(class_name_c.as_ptr()) };
        if class.is_null() {
            return Ok(Vec::new());
        }

        let mut count = 0u32;
        let list = unsafe { class_copyIvarList(class, &mut count as *mut u32) };
        if list.is_null() {
            return Ok(Vec::new());
        }

        let slice = unsafe { std::slice::from_raw_parts(list, count as usize) };
        let mut ivars = Vec::with_capacity(slice.len());
        for ivar in slice {
            if ivar.is_null() {
                continue;
            }

            let name = unsafe { ivar_getName(*ivar as *const c_void) };
            if name.is_null() {
                continue;
            }

            let type_encoding = unsafe { ivar_getTypeEncoding(*ivar as *const c_void) };
            let offset = unsafe { ivar_getOffset(*ivar as *const c_void) };
            if offset < 0 {
                continue;
            }

            ivars.push(ObjcIvarInfo {
                class_name: class_name.to_string(),
                ivar_name: unsafe { CStr::from_ptr(name) }.to_string_lossy().into_owned(),
                type_encoding: if type_encoding.is_null() {
                    String::new()
                } else {
                    unsafe { CStr::from_ptr(type_encoding) }.to_string_lossy().into_owned()
                },
                offset: offset as usize,
            });
        }

        unsafe { libc::free(list.cast()) };
        ivars.sort_by(|left, right| {
            left.ivar_name
                .cmp(&right.ivar_name)
                .then(left.offset.cmp(&right.offset))
        });
        ivars.dedup_by(|left, right| {
            left.ivar_name == right.ivar_name
                && left.type_encoding == right.type_encoding
                && left.offset == right.offset
        });
        Ok(ivars)
    }

    pub fn find_ivars(class_name: &str, query: &str) -> Result<Vec<ObjcIvarInfo>> {
        let trimmed = query.trim();
        if trimmed.is_empty() {
            return Err(Error::InvalidArgument("ivar query must not be empty".into()));
        }

        let mut ivars = enumerate_ivars(class_name)?;
        ivars.retain(|ivar| query_matches_ivar_name(&ivar.ivar_name, trimmed));
        Ok(ivars)
    }

    fn resolve_method(class_name: &str, selector_name: &str, is_class_method: bool) -> Result<Option<ResolvedMethod>> {
        let class_name =
            CString::new(class_name).map_err(|_| Error::InvalidArgument("class name contains interior NUL".into()))?;
        let selector_name =
            CString::new(selector_name).map_err(|_| Error::InvalidArgument("selector contains interior NUL".into()))?;

        let class = unsafe { objc_getClass(class_name.as_ptr()) };
        if class.is_null() {
            return Ok(None);
        }

        let selector = unsafe { sel_registerName(selector_name.as_ptr()) };
        let lookup_class = if is_class_method {
            unsafe { object_getClass(class) }
        } else {
            class
        };
        if lookup_class.is_null() {
            return Ok(None);
        }

        let method = unsafe {
            if is_class_method {
                class_getClassMethod(class, selector)
            } else {
                class_getInstanceMethod(lookup_class, selector)
            }
        };
        if method.is_null() {
            return Ok(None);
        }

        let type_encoding = unsafe { method_getTypeEncoding(method as *const c_void) };
        Ok(Some(ResolvedMethod {
            method_pointer: method as usize,
            imp: unsafe { method_getImplementation(method as *const c_void) } as usize,
            type_encoding: if type_encoding.is_null() {
                String::new()
            } else {
                unsafe { CStr::from_ptr(type_encoding) }.to_string_lossy().into_owned()
            },
        }))
    }

    pub fn method_imp(class_name: &str, selector_name: &str, is_class_method: bool) -> Result<Option<usize>> {
        Ok(resolve_method(class_name, selector_name, is_class_method)?.map(|method| method.imp))
    }

    pub fn method_info(
        class_name: &str,
        selector_name: &str,
        is_class_method: bool,
    ) -> Result<Option<ObjcMethodDetail>> {
        let class_name = class_name.trim();
        if class_name.is_empty() {
            return Err(Error::InvalidArgument("class name must not be empty".into()));
        }

        let selector_name = selector_name.trim();
        if selector_name.is_empty() {
            return Err(Error::InvalidArgument("selector name must not be empty".into()));
        }

        let Some(method) = resolve_method(class_name, selector_name, is_class_method)? else {
            return Ok(None);
        };

        let image_path = image_path_for_address(method.imp as *const c_void)?;
        Ok(Some(ObjcMethodDetail {
            class_name: class_name.to_string(),
            selector_name: selector_name.to_string(),
            method_pointer: method.method_pointer,
            imp: method.imp,
            type_encoding: method.type_encoding,
            is_class_method,
            image_path,
        }))
    }

    pub fn class_image(class_name: &str) -> Result<Option<String>> {
        let class_name =
            CString::new(class_name).map_err(|_| Error::InvalidArgument("class name contains interior NUL".into()))?;
        let class = unsafe { objc_getClass(class_name.as_ptr()) };
        if class.is_null() {
            return Ok(None);
        }

        image_path_for_address(class as *const c_void)
    }

    pub fn method_image(class_name: &str, selector_name: &str, is_class_method: bool) -> Result<Option<String>> {
        let Some(address) = method_imp(class_name, selector_name, is_class_method)? else {
            return Ok(None);
        };

        image_path_for_address(address as *const c_void)
    }

    pub fn enumerate_methods(class_name: &str, is_class_method: bool) -> Result<Vec<ObjcMethodInfo>> {
        let class_name = class_name.trim();
        if class_name.is_empty() {
            return Err(Error::InvalidArgument("class name must not be empty".into()));
        }

        let class_name_c =
            CString::new(class_name).map_err(|_| Error::InvalidArgument("class name contains interior NUL".into()))?;
        let class = unsafe { objc_getClass(class_name_c.as_ptr()) };
        if class.is_null() {
            return Ok(Vec::new());
        }

        let lookup_class = if is_class_method {
            unsafe { object_getClass(class) }
        } else {
            class
        };
        if lookup_class.is_null() {
            return Ok(Vec::new());
        }

        let mut count = 0u32;
        let list = unsafe { class_copyMethodList(lookup_class, &mut count as *mut u32) };
        if list.is_null() {
            return Ok(Vec::new());
        }

        let slice = unsafe { std::slice::from_raw_parts(list, count as usize) };
        let mut methods = Vec::with_capacity(slice.len());
        for method in slice {
            if method.is_null() {
                continue;
            }

            let selector = unsafe { method_getName(*method as *const c_void) };
            if selector.is_null() {
                continue;
            }

            let selector_name = unsafe { sel_getName(selector) };
            if selector_name.is_null() {
                continue;
            }

            methods.push(ObjcMethodInfo {
                class_name: class_name.to_string(),
                selector_name: unsafe { CStr::from_ptr(selector_name) }.to_string_lossy().into_owned(),
                imp: unsafe { method_getImplementation(*method as *const c_void) } as usize,
                type_encoding: {
                    let type_encoding = unsafe { method_getTypeEncoding(*method as *const c_void) };
                    if type_encoding.is_null() {
                        String::new()
                    } else {
                        unsafe { CStr::from_ptr(type_encoding) }.to_string_lossy().into_owned()
                    }
                },
                is_class_method,
            });
        }

        unsafe { libc::free(list.cast()) };
        methods.sort_by(|left, right| {
            left.selector_name
                .cmp(&right.selector_name)
                .then(left.type_encoding.cmp(&right.type_encoding))
                .then(left.imp.cmp(&right.imp))
        });
        methods.dedup_by(|left, right| {
            left.selector_name == right.selector_name
                && left.type_encoding == right.type_encoding
                && left.imp == right.imp
                && left.is_class_method == right.is_class_method
        });
        Ok(methods)
    }

    pub fn find_methods(class_name: &str, query: &str, is_class_method: bool) -> Result<Vec<ObjcMethodInfo>> {
        let trimmed = query.trim();
        if trimmed.is_empty() {
            return Err(Error::InvalidArgument("method query must not be empty".into()));
        }

        let mut methods = enumerate_methods(class_name, is_class_method)?;
        methods.retain(|method| query_matches_method_name(&method.selector_name, trimmed));
        Ok(methods)
    }

    pub fn find_method_owners(query: &str, is_class_method: bool) -> Result<Vec<ObjcMethodInfo>> {
        let trimmed = query.trim();
        if trimmed.is_empty() {
            return Err(Error::InvalidArgument("method query must not be empty".into()));
        }

        let mut class_count = 0u32;
        let class_list = unsafe { objc_copyClassList(&mut class_count as *mut u32) };
        if class_list.is_null() {
            return Ok(Vec::new());
        }

        let classes = unsafe { std::slice::from_raw_parts(class_list, class_count as usize) };
        let mut methods = Vec::new();

        for class in classes {
            if class.is_null() {
                continue;
            }

            let class_name = unsafe { class_getName(*class as *const c_void) };
            if class_name.is_null() {
                continue;
            }
            let class_name = unsafe { CStr::from_ptr(class_name) }.to_string_lossy().into_owned();

            let lookup_class = if is_class_method {
                unsafe { object_getClass(*class as *const c_void) }
            } else {
                *class
            };
            if lookup_class.is_null() {
                continue;
            }

            let mut method_count = 0u32;
            let method_list = unsafe { class_copyMethodList(lookup_class, &mut method_count as *mut u32) };
            if method_list.is_null() {
                continue;
            }

            let method_slice = unsafe { std::slice::from_raw_parts(method_list, method_count as usize) };
            for method in method_slice {
                if method.is_null() {
                    continue;
                }

                let selector = unsafe { method_getName(*method as *const c_void) };
                if selector.is_null() {
                    continue;
                }

                let selector_name = unsafe { sel_getName(selector) };
                if selector_name.is_null() {
                    continue;
                }

                let selector_name = unsafe { CStr::from_ptr(selector_name) }.to_string_lossy().into_owned();
                if !query_matches_method_name(&selector_name, trimmed) {
                    continue;
                }

                methods.push(ObjcMethodInfo {
                    class_name: class_name.clone(),
                    selector_name,
                    imp: unsafe { method_getImplementation(*method as *const c_void) } as usize,
                    type_encoding: {
                        let type_encoding = unsafe { method_getTypeEncoding(*method as *const c_void) };
                        if type_encoding.is_null() {
                            String::new()
                        } else {
                            unsafe { CStr::from_ptr(type_encoding) }.to_string_lossy().into_owned()
                        }
                    },
                    is_class_method,
                });
            }

            unsafe { libc::free(method_list.cast()) };
        }

        unsafe { libc::free(class_list.cast()) };

        methods.sort_by(|left, right| {
            left.class_name
                .cmp(&right.class_name)
                .then(left.selector_name.cmp(&right.selector_name))
                .then(left.type_encoding.cmp(&right.type_encoding))
                .then(left.imp.cmp(&right.imp))
        });
        methods.dedup_by(|left, right| {
            left.class_name == right.class_name
                && left.selector_name == right.selector_name
                && left.type_encoding == right.type_encoding
                && left.imp == right.imp
        });
        Ok(methods)
    }

    pub fn selector_name(selector: usize) -> Result<Option<String>> {
        if selector == 0 {
            return Ok(None);
        }

        let name = unsafe { sel_getName(selector as *const c_void) };
        if name.is_null() {
            return Ok(None);
        }

        Ok(Some(unsafe { CStr::from_ptr(name) }.to_string_lossy().into_owned()))
    }

    pub fn object_class_name(object: usize) -> Result<Option<String>> {
        if object == 0 {
            return Ok(None);
        }

        let class = unsafe { object_getClass(object as *const c_void) };
        if class.is_null() {
            return Ok(None);
        }

        let name = unsafe { class_getName(class) };
        if name.is_null() {
            return Ok(None);
        }

        Ok(Some(unsafe { CStr::from_ptr(name) }.to_string_lossy().into_owned()))
    }

    fn image_path_for_address(address: *const c_void) -> Result<Option<String>> {
        if address.is_null() {
            return Ok(None);
        }

        let mut info = DlInfo {
            dli_fname: std::ptr::null(),
            dli_fbase: std::ptr::null_mut(),
            dli_sname: std::ptr::null(),
            dli_saddr: std::ptr::null_mut(),
        };
        let status = unsafe { dladdr(address, &mut info as *mut DlInfo) };
        if status == 0 || info.dli_fname.is_null() {
            return Ok(None);
        }

        Ok(Some(
            unsafe { CStr::from_ptr(info.dli_fname) }.to_string_lossy().into_owned(),
        ))
    }
}

#[cfg(not(any(target_os = "ios", target_os = "macos")))]
mod platform {
    use common::Result;

    use crate::{
        ObjcClassInfo, ObjcIvarDetail, ObjcIvarInfo, ObjcMethodDetail, ObjcMethodInfo, ObjcPropertyDetail,
        ObjcPropertyInfo, ObjcProtocolInfo, ObjcProtocolMethodDetail, ObjcProtocolMethodInfo,
        ObjcProtocolPropertyDetail, ObjcProtocolPropertyInfo,
    };

    pub fn class_exists(_name: &str) -> bool {
        false
    }

    pub fn enumerate_classes() -> Result<Vec<String>> {
        Err(common::Error::Unsupported(
            "Objective-C runtime is only available on Apple targets".into(),
        ))
    }

    pub fn find_classes(_query: &str) -> Result<Vec<String>> {
        Err(common::Error::Unsupported(
            "Objective-C runtime is only available on Apple targets".into(),
        ))
    }

    pub fn selector(_name: &str) -> Result<usize> {
        Err(common::Error::Unsupported(
            "Objective-C runtime is only available on Apple targets".into(),
        ))
    }

    pub fn enumerate_protocols() -> Result<Vec<String>> {
        Err(common::Error::Unsupported(
            "Objective-C runtime is only available on Apple targets".into(),
        ))
    }

    pub fn find_protocols(_query: &str) -> Result<Vec<String>> {
        Err(common::Error::Unsupported(
            "Objective-C runtime is only available on Apple targets".into(),
        ))
    }

    pub fn class_protocols(_class_name: &str) -> Result<Vec<String>> {
        Err(common::Error::Unsupported(
            "Objective-C runtime is only available on Apple targets".into(),
        ))
    }

    pub fn enumerate_properties(_class_name: &str, _is_class_property: bool) -> Result<Vec<ObjcPropertyInfo>> {
        Err(common::Error::Unsupported(
            "Objective-C runtime is only available on Apple targets".into(),
        ))
    }

    pub fn property_info(
        _class_name: &str,
        _property_name: &str,
        _is_class_property: bool,
    ) -> Result<Option<ObjcPropertyDetail>> {
        Err(common::Error::Unsupported(
            "Objective-C runtime is only available on Apple targets".into(),
        ))
    }

    pub fn superclass(_class_name: &str) -> Result<Option<String>> {
        Err(common::Error::Unsupported(
            "Objective-C runtime is only available on Apple targets".into(),
        ))
    }

    pub fn class_chain(_class_name: &str) -> Result<Vec<String>> {
        Err(common::Error::Unsupported(
            "Objective-C runtime is only available on Apple targets".into(),
        ))
    }

    pub fn class_info(_class_name: &str, _is_meta_class: bool) -> Result<Option<ObjcClassInfo>> {
        Err(common::Error::Unsupported(
            "Objective-C runtime is only available on Apple targets".into(),
        ))
    }

    pub fn protocol_info(_protocol_name: &str) -> Result<Option<ObjcProtocolInfo>> {
        Err(common::Error::Unsupported(
            "Objective-C runtime is only available on Apple targets".into(),
        ))
    }

    pub fn protocol_methods(
        _protocol_name: &str,
        _is_required: bool,
        _is_instance_method: bool,
    ) -> Result<Vec<ObjcProtocolMethodInfo>> {
        Err(common::Error::Unsupported(
            "Objective-C runtime is only available on Apple targets".into(),
        ))
    }

    pub fn protocol_method_info(
        _protocol_name: &str,
        _selector_name: &str,
        _is_required: bool,
        _is_instance_method: bool,
    ) -> Result<Option<ObjcProtocolMethodDetail>> {
        Err(common::Error::Unsupported(
            "Objective-C runtime is only available on Apple targets".into(),
        ))
    }

    pub fn protocol_properties(_protocol_name: &str) -> Result<Vec<ObjcProtocolPropertyInfo>> {
        Err(common::Error::Unsupported(
            "Objective-C runtime is only available on Apple targets".into(),
        ))
    }

    pub fn protocol_property_info(
        _protocol_name: &str,
        _property_name: &str,
    ) -> Result<Option<ObjcProtocolPropertyDetail>> {
        Err(common::Error::Unsupported(
            "Objective-C runtime is only available on Apple targets".into(),
        ))
    }

    pub fn protocol_protocols(_protocol_name: &str) -> Result<Vec<String>> {
        Err(common::Error::Unsupported(
            "Objective-C runtime is only available on Apple targets".into(),
        ))
    }

    pub fn find_properties(_class_name: &str, _query: &str, _is_class_property: bool) -> Result<Vec<ObjcPropertyInfo>> {
        Err(common::Error::Unsupported(
            "Objective-C runtime is only available on Apple targets".into(),
        ))
    }

    pub fn enumerate_ivars(_class_name: &str) -> Result<Vec<ObjcIvarInfo>> {
        Err(common::Error::Unsupported(
            "Objective-C runtime is only available on Apple targets".into(),
        ))
    }

    pub fn ivar_info(_class_name: &str, _ivar_name: &str) -> Result<Option<ObjcIvarDetail>> {
        Err(common::Error::Unsupported(
            "Objective-C runtime is only available on Apple targets".into(),
        ))
    }

    pub fn find_ivars(_class_name: &str, _query: &str) -> Result<Vec<ObjcIvarInfo>> {
        Err(common::Error::Unsupported(
            "Objective-C runtime is only available on Apple targets".into(),
        ))
    }

    pub fn method_imp(_class_name: &str, _selector_name: &str, _is_class_method: bool) -> Result<Option<usize>> {
        Err(common::Error::Unsupported(
            "Objective-C runtime is only available on Apple targets".into(),
        ))
    }

    pub fn method_info(
        _class_name: &str,
        _selector_name: &str,
        _is_class_method: bool,
    ) -> Result<Option<ObjcMethodDetail>> {
        Err(common::Error::Unsupported(
            "Objective-C runtime is only available on Apple targets".into(),
        ))
    }

    pub fn enumerate_methods(_class_name: &str, _is_class_method: bool) -> Result<Vec<ObjcMethodInfo>> {
        Err(common::Error::Unsupported(
            "Objective-C runtime is only available on Apple targets".into(),
        ))
    }

    pub fn find_methods(_class_name: &str, _query: &str, _is_class_method: bool) -> Result<Vec<ObjcMethodInfo>> {
        Err(common::Error::Unsupported(
            "Objective-C runtime is only available on Apple targets".into(),
        ))
    }

    pub fn find_method_owners(_query: &str, _is_class_method: bool) -> Result<Vec<ObjcMethodInfo>> {
        Err(common::Error::Unsupported(
            "Objective-C runtime is only available on Apple targets".into(),
        ))
    }

    pub fn class_image(_class_name: &str) -> Result<Option<String>> {
        Err(common::Error::Unsupported(
            "Objective-C runtime is only available on Apple targets".into(),
        ))
    }

    pub fn method_image(_class_name: &str, _selector_name: &str, _is_class_method: bool) -> Result<Option<String>> {
        Err(common::Error::Unsupported(
            "Objective-C runtime is only available on Apple targets".into(),
        ))
    }

    pub fn selector_name(_selector: usize) -> Result<Option<String>> {
        Err(common::Error::Unsupported(
            "Objective-C runtime is only available on Apple targets".into(),
        ))
    }

    pub fn object_class_name(_object: usize) -> Result<Option<String>> {
        Err(common::Error::Unsupported(
            "Objective-C runtime is only available on Apple targets".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        query_matches_class_name, query_matches_ivar_name, query_matches_method_name, query_matches_property_name,
        ObjcApi,
    };

    #[test]
    fn class_query_matches_case_insensitively() {
        assert!(query_matches_class_name("UIViewController", "view"));
        assert!(query_matches_class_name("UIViewController", "CONTROLLER"));
        assert!(!query_matches_class_name("UIViewController", "appdelegate"));
    }

    #[test]
    fn method_query_matches_case_insensitively() {
        assert!(query_matches_method_name("viewDidLoad", "view"));
        assert!(query_matches_method_name("viewDidLoad", "DIDLOAD"));
        assert!(!query_matches_method_name("viewDidLoad", "applicationdidfinish"));
    }

    #[test]
    fn property_query_matches_case_insensitively() {
        assert!(query_matches_property_name("delegate", "dele"));
        assert!(query_matches_property_name("delegate", "LEG"));
        assert!(!query_matches_property_name("delegate", "window"));
    }

    #[test]
    fn ivar_query_matches_case_insensitively() {
        assert!(query_matches_ivar_name("_delegate", "dele"));
        assert!(query_matches_ivar_name("_delegate", "LEG"));
        assert!(!query_matches_ivar_name("_delegate", "window"));
    }

    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    #[test]
    fn enumerate_protocols_is_unsupported_on_non_apple_targets() {
        let err = ObjcApi::new()
            .enumerate_protocols()
            .expect_err("non-Apple targets should not expose ObjC runtime");
        assert!(err
            .to_string()
            .contains("Objective-C runtime is only available on Apple targets"));
    }

    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    #[test]
    fn find_protocols_is_unsupported_on_non_apple_targets() {
        let err = ObjcApi::new()
            .find_protocols("NS")
            .expect_err("non-Apple targets should not expose ObjC runtime");
        assert!(err
            .to_string()
            .contains("Objective-C runtime is only available on Apple targets"));
    }

    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    #[test]
    fn class_protocols_is_unsupported_on_non_apple_targets() {
        let err = ObjcApi::new()
            .class_protocols("NSObject")
            .expect_err("non-Apple targets should not expose ObjC runtime");
        assert!(err
            .to_string()
            .contains("Objective-C runtime is only available on Apple targets"));
    }

    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    #[test]
    fn protocol_properties_is_unsupported_on_non_apple_targets() {
        let err = ObjcApi::new()
            .protocol_properties("NSObject")
            .expect_err("non-Apple targets should not expose ObjC runtime");
        assert!(err
            .to_string()
            .contains("Objective-C runtime is only available on Apple targets"));
    }

    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    #[test]
    fn protocol_property_info_is_unsupported_on_non_apple_targets() {
        let err = ObjcApi::new()
            .protocol_property_info("NSObject", "description")
            .expect_err("non-Apple targets should not expose ObjC runtime");
        assert!(err
            .to_string()
            .contains("Objective-C runtime is only available on Apple targets"));
    }

    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    #[test]
    fn protocol_protocols_is_unsupported_on_non_apple_targets() {
        let err = ObjcApi::new()
            .protocol_protocols("NSObject")
            .expect_err("non-Apple targets should not expose ObjC runtime");
        assert!(err
            .to_string()
            .contains("Objective-C runtime is only available on Apple targets"));
    }

    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    #[test]
    fn superclass_is_unsupported_on_non_apple_targets() {
        let err = ObjcApi::new()
            .superclass("NSObject")
            .expect_err("non-Apple targets should not expose ObjC runtime");
        assert!(err
            .to_string()
            .contains("Objective-C runtime is only available on Apple targets"));
    }

    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    #[test]
    fn class_chain_is_unsupported_on_non_apple_targets() {
        let err = ObjcApi::new()
            .class_chain("NSObject")
            .expect_err("non-Apple targets should not expose ObjC runtime");
        assert!(err
            .to_string()
            .contains("Objective-C runtime is only available on Apple targets"));
    }

    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    #[test]
    fn class_info_is_unsupported_on_non_apple_targets() {
        let err = ObjcApi::new()
            .class_info("NSObject", false)
            .expect_err("non-Apple targets should not expose ObjC runtime");
        assert!(err
            .to_string()
            .contains("Objective-C runtime is only available on Apple targets"));
    }

    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    #[test]
    fn protocol_info_is_unsupported_on_non_apple_targets() {
        let err = ObjcApi::new()
            .protocol_info("NSObject")
            .expect_err("non-Apple targets should not expose ObjC runtime");
        assert!(err
            .to_string()
            .contains("Objective-C runtime is only available on Apple targets"));
    }

    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    #[test]
    fn protocol_methods_is_unsupported_on_non_apple_targets() {
        let err = ObjcApi::new()
            .protocol_methods("NSObject", true, true)
            .expect_err("non-Apple targets should not expose ObjC runtime");
        assert!(err
            .to_string()
            .contains("Objective-C runtime is only available on Apple targets"));
    }

    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    #[test]
    fn protocol_method_info_is_unsupported_on_non_apple_targets() {
        let err = ObjcApi::new()
            .protocol_method_info("NSObject", "description", true, true)
            .expect_err("non-Apple targets should not expose ObjC runtime");
        assert!(err
            .to_string()
            .contains("Objective-C runtime is only available on Apple targets"));
    }

    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    #[test]
    fn enumerate_properties_is_unsupported_on_non_apple_targets() {
        let err = ObjcApi::new()
            .enumerate_properties("NSObject", false)
            .expect_err("non-Apple targets should not expose ObjC runtime");
        assert!(err
            .to_string()
            .contains("Objective-C runtime is only available on Apple targets"));
    }

    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    #[test]
    fn property_info_is_unsupported_on_non_apple_targets() {
        let err = ObjcApi::new()
            .property_info("NSObject", "description", false)
            .expect_err("non-Apple targets should not expose ObjC runtime");
        assert!(err
            .to_string()
            .contains("Objective-C runtime is only available on Apple targets"));
    }

    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    #[test]
    fn find_properties_is_unsupported_on_non_apple_targets() {
        let err = ObjcApi::new()
            .find_properties("NSObject", "delegate", false)
            .expect_err("non-Apple targets should not expose ObjC runtime");
        assert!(err
            .to_string()
            .contains("Objective-C runtime is only available on Apple targets"));
    }

    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    #[test]
    fn enumerate_ivars_is_unsupported_on_non_apple_targets() {
        let err = ObjcApi::new()
            .enumerate_ivars("NSObject")
            .expect_err("non-Apple targets should not expose ObjC runtime");
        assert!(err
            .to_string()
            .contains("Objective-C runtime is only available on Apple targets"));
    }

    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    #[test]
    fn ivar_info_is_unsupported_on_non_apple_targets() {
        let err = ObjcApi::new()
            .ivar_info("NSObject", "_isa")
            .expect_err("non-Apple targets should not expose ObjC runtime");
        assert!(err
            .to_string()
            .contains("Objective-C runtime is only available on Apple targets"));
    }

    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    #[test]
    fn find_ivars_is_unsupported_on_non_apple_targets() {
        let err = ObjcApi::new()
            .find_ivars("NSObject", "delegate")
            .expect_err("non-Apple targets should not expose ObjC runtime");
        assert!(err
            .to_string()
            .contains("Objective-C runtime is only available on Apple targets"));
    }

    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    #[test]
    fn enumerate_methods_is_unsupported_on_non_apple_targets() {
        let err = ObjcApi::new()
            .enumerate_methods("NSObject", false)
            .expect_err("non-Apple targets should not expose ObjC runtime");
        assert!(err
            .to_string()
            .contains("Objective-C runtime is only available on Apple targets"));
    }

    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    #[test]
    fn method_info_is_unsupported_on_non_apple_targets() {
        let err = ObjcApi::new()
            .method_info("NSObject", "init", false)
            .expect_err("non-Apple targets should not expose ObjC runtime");
        assert!(err
            .to_string()
            .contains("Objective-C runtime is only available on Apple targets"));
    }

    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    #[test]
    fn find_method_owners_is_unsupported_on_non_apple_targets() {
        let err = ObjcApi::new()
            .find_method_owners("init", false)
            .expect_err("non-Apple targets should not expose ObjC runtime");
        assert!(err
            .to_string()
            .contains("Objective-C runtime is only available on Apple targets"));
    }

    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    #[test]
    fn class_and_method_image_are_unsupported_on_non_apple_targets() {
        let class_err = ObjcApi::new()
            .class_image("NSObject")
            .expect_err("non-Apple targets should not expose ObjC runtime");
        assert!(class_err
            .to_string()
            .contains("Objective-C runtime is only available on Apple targets"));

        let method_err = ObjcApi::new()
            .method_image("NSObject", "init", false)
            .expect_err("non-Apple targets should not expose ObjC runtime");
        assert!(method_err
            .to_string()
            .contains("Objective-C runtime is only available on Apple targets"));
    }
}
