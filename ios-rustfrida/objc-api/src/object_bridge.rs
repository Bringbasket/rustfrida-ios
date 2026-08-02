//! Bounded Objective-C object operations for the Apple runtime.
//!
//! Raw object construction is intentionally `unsafe`: checking VM permissions
//! can reject obvious bad pointers, but it cannot prove that arbitrary mapped
//! memory is a live Objective-C object. Callers must obtain pointers from a
//! trusted Objective-C/runtime boundary and guarantee their lifetime while a
//! retained handle is being created.

use std::fmt;
use std::marker::PhantomData;
use std::mem::ManuallyDrop;
use std::num::NonZeroUsize;
use std::rc::Rc;

pub const MAX_MESSAGE_ARGUMENTS: usize = 6;
pub const MAX_SYNTHESIZED_PROPERTY_NAME_LENGTH: usize = 255;

pub type BridgeResult<T> = Result<T, BridgeError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropertyOwnership {
    Assign,
    Retain,
    Copy,
    Weak,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropertyKvo {
    Automatic,
    Manual,
}

impl PropertyKvo {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Automatic => "automatic",
            Self::Manual => "manual",
        }
    }
}

impl PropertyOwnership {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Assign => "assign",
            Self::Retain => "retain",
            Self::Copy => "copy",
            Self::Weak => "weak",
        }
    }

    const fn requires_managed_lifecycle(self) -> bool {
        !matches!(self, Self::Assign)
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SynthesizedPropertyOptions {
    pub read_only: bool,
    pub ownership: PropertyOwnership,
    pub atomic: bool,
    pub kvo: PropertyKvo,
    pub getter: Option<String>,
    pub setter: Option<String>,
}

impl SynthesizedPropertyOptions {
    pub const fn new(read_only: bool, ownership: PropertyOwnership) -> Self {
        Self {
            read_only,
            ownership,
            atomic: false,
            kvo: PropertyKvo::Automatic,
            getter: None,
            setter: None,
        }
    }

    pub fn with_getter(mut self, getter: impl Into<String>) -> Self {
        self.getter = Some(getter.into());
        self
    }

    pub fn with_setter(mut self, setter: impl Into<String>) -> Self {
        self.setter = Some(setter.into());
        self
    }

    pub const fn with_atomic(mut self, atomic: bool) -> Self {
        self.atomic = atomic;
        self
    }

    pub const fn with_kvo(mut self, kvo: PropertyKvo) -> Self {
        self.kvo = kvo;
        self
    }
}

impl Default for SynthesizedPropertyOptions {
    fn default() -> Self {
        Self::new(false, PropertyOwnership::Assign)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjcException {
    pub name: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeError {
    PlatformUnavailable,
    NullPointer,
    MisalignedObjectPointer {
        address: usize,
        alignment: usize,
    },
    InvalidName {
        kind: &'static str,
        reason: &'static str,
    },
    InvalidObjectPointer {
        address: usize,
        reason: String,
    },
    InvalidMemoryRange {
        address: usize,
        length: usize,
        reason: String,
    },
    ClassNotFound(String),
    IvarNotFound(String),
    IvarOutOfBounds {
        name: String,
        offset: usize,
        width: usize,
        instance_size: usize,
    },
    TooManyArguments {
        supplied: usize,
        maximum: usize,
    },
    VoidArgument {
        index: usize,
    },
    ValueOutOfRange {
        kind: ScalarKind,
    },
    IvarTypeMismatch {
        name: String,
        requested: ScalarKind,
        encoding: String,
    },
    ObjectiveCException(ObjcException),
    ShimContractViolation {
        operation: &'static str,
        status: i32,
    },
    ClassAllocationFailed(String),
    ClassMutationFailed {
        class_name: String,
        member_name: String,
        operation: &'static str,
    },
    InvalidIvarLayout {
        size: usize,
        alignment: usize,
    },
    UnsupportedPropertyType {
        encoding: String,
    },
    UnsupportedPropertyOwnership {
        encoding: String,
        ownership: PropertyOwnership,
    },
    NullImplementation,
    ExceptionContainmentUnavailable,
}

impl fmt::Display for BridgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PlatformUnavailable => write!(f, "Objective-C object operations are only available on Apple targets"),
            Self::NullPointer => write!(f, "Objective-C object pointer is null"),
            Self::MisalignedObjectPointer { address, alignment } => write!(
                f,
                "Objective-C object pointer {address:#x} is not aligned to {alignment} bytes; tagged pointers are not accepted by this bridge"
            ),
            Self::InvalidName { kind, reason } => write!(f, "invalid {kind} name: {reason}"),
            Self::InvalidObjectPointer { address, reason } => {
                write!(f, "invalid Objective-C object pointer {address:#x}: {reason}")
            }
            Self::InvalidMemoryRange {
                address,
                length,
                reason,
            } => write!(f, "invalid memory range {address:#x}+{length:#x}: {reason}"),
            Self::ClassNotFound(name) => write!(f, "Objective-C class not found: {name}"),
            Self::IvarNotFound(name) => write!(f, "Objective-C ivar not found: {name}"),
            Self::IvarOutOfBounds {
                name,
                offset,
                width,
                instance_size,
            } => write!(
                f,
                "Objective-C ivar {name} range {offset:#x}+{width:#x} exceeds instance size {instance_size:#x}"
            ),
            Self::TooManyArguments { supplied, maximum } => {
                write!(f, "objc_msgSend received {supplied} explicit arguments; maximum is {maximum}")
            }
            Self::VoidArgument { index } => write!(f, "objc_msgSend argument {index} has void type"),
            Self::ValueOutOfRange { kind } => write!(f, "{kind:?} value does not fit the target pointer width"),
            Self::IvarTypeMismatch {
                name,
                requested,
                encoding,
            } => write!(
                f,
                "Objective-C ivar {name} has encoding {encoding:?}, which is incompatible with {requested:?}"
            ),
            Self::ObjectiveCException(exception) => match (&exception.name, &exception.reason) {
                (Some(name), Some(reason)) => write!(f, "Objective-C exception {name}: {reason}"),
                (Some(name), None) => write!(f, "Objective-C exception {name}"),
                (None, Some(reason)) => write!(f, "Objective-C exception: {reason}"),
                (None, None) => write!(f, "Objective-C exception (details unavailable)"),
            },
            Self::ShimContractViolation { operation, status } => {
                write!(f, "Objective-C shim contract violation during {operation}: status={status}")
            }
            Self::ClassAllocationFailed(name) => write!(f, "Objective-C class allocation failed: {name}"),
            Self::ClassMutationFailed {
                class_name,
                member_name,
                operation,
            } => write!(f, "Objective-C class {class_name} rejected {operation} for {member_name}"),
            Self::InvalidIvarLayout { size, alignment } => {
                write!(f, "invalid Objective-C ivar layout: size={size}, alignment={alignment}")
            }
            Self::UnsupportedPropertyType { encoding } => write!(
                f,
                "Objective-C synthesized properties support scalar and pointer encodings only: {encoding:?}"
            ),
            Self::UnsupportedPropertyOwnership { encoding, ownership } => write!(
                f,
                "Objective-C {} property ownership requires an object encoding, got {encoding:?}",
                ownership.name()
            ),
            Self::NullImplementation => write!(f, "Objective-C method implementation pointer is null"),
            Self::ExceptionContainmentUnavailable => write!(
                f,
                "Objective-C exception containment is unavailable on this target"
            ),
        }
    }
}

impl std::error::Error for BridgeError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjcExceptionBoundary {
    ContainedByAppleShim,
    PlatformUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectBridgeCapabilities {
    pub available: bool,
    pub max_message_arguments: usize,
    pub catches_objc_exceptions: bool,
    pub accepts_tagged_object_pointers: bool,
    pub supports_scalar_and_pointer_dispatch: bool,
    pub supports_raw_ivar_access: bool,
    pub supports_property_accessors: bool,
    pub supports_dynamic_class_registration: bool,
    pub supports_dynamic_property_synthesis: bool,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ObjectBridge;

impl ObjectBridge {
    pub const fn new() -> Self {
        Self
    }

    pub const fn is_available(self) -> bool {
        cfg!(any(target_os = "ios", target_os = "macos"))
    }

    pub const fn capabilities(self) -> ObjectBridgeCapabilities {
        ObjectBridgeCapabilities {
            available: self.is_available(),
            max_message_arguments: MAX_MESSAGE_ARGUMENTS,
            catches_objc_exceptions: self.is_available(),
            accepts_tagged_object_pointers: false,
            supports_scalar_and_pointer_dispatch: self.is_available(),
            supports_raw_ivar_access: self.is_available(),
            supports_property_accessors: self.is_available(),
            supports_dynamic_class_registration: self.is_available(),
            supports_dynamic_property_synthesis: self.is_available(),
        }
    }

    pub const fn exception_boundary(self) -> ObjcExceptionBoundary {
        if self.is_available() {
            ObjcExceptionBoundary::ContainedByAppleShim
        } else {
            ObjcExceptionBoundary::PlatformUnavailable
        }
    }

    pub fn require_caught_exceptions(self) -> BridgeResult<()> {
        if self.is_available() {
            Ok(())
        } else {
            Err(BridgeError::ExceptionContainmentUnavailable)
        }
    }

    pub fn lookup_class(self, name: &str) -> BridgeResult<Option<ObjcClass>> {
        ObjcClass::lookup(name)
    }

    pub fn require_class(self, name: &str) -> BridgeResult<ObjcClass> {
        ObjcClass::require(name)
    }

    pub fn register_selector(self, name: &str) -> BridgeResult<ObjcSelector> {
        ObjcSelector::register(name)
    }

    pub fn allocate_subclass(self, superclass_name: &str, name: &str) -> BridgeResult<PendingObjcClass> {
        let superclass_name = checked_name(superclass_name, "superclass")?;
        let name = checked_name(name, "class")?;
        let superclass = ObjcClass::require(superclass_name)?;
        PendingObjcClass::allocate(superclass, name)
    }

    /// Performs the bridge's conservative VM and runtime-class checks without
    /// taking ownership of the object.
    ///
    /// # Safety
    ///
    /// `raw` must remain a live Objective-C object while the runtime probes it.
    /// A successful result is a point-in-time check, not a lifetime guarantee.
    pub unsafe fn validate_object_pointer(self, raw: usize) -> BridgeResult<()> {
        platform::validate_object(raw)
    }

    /// Retains a trusted live Objective-C object pointer and returns an owned
    /// handle. VM validation narrows the input surface but is inherently racy.
    ///
    /// # Safety
    ///
    /// `raw` must identify a live, non-tagged Objective-C object for the full
    /// duration of validation and `objc_retain`.
    pub unsafe fn retain_object(self, raw: usize) -> BridgeResult<ObjcObject> {
        unsafe { ObjcObject::retain_raw(raw) }
    }

    /// Adopts an existing +1 Objective-C ownership reference.
    ///
    /// # Safety
    ///
    /// `raw` must be a live, non-tagged Objective-C object carrying one owned
    /// reference that is transferred only when this function returns `Ok`.
    pub unsafe fn adopt_retained_object(self, raw: usize) -> BridgeResult<ObjcObject> {
        unsafe { ObjcObject::from_retained_raw(raw) }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObjcClass(NonZeroUsize);

impl ObjcClass {
    pub fn lookup(name: &str) -> BridgeResult<Option<Self>> {
        let name = checked_name(name, "class")?;
        platform::lookup_class(name).map(|raw| raw.and_then(NonZeroUsize::new).map(Self))
    }

    pub fn require(name: &str) -> BridgeResult<Self> {
        Self::lookup(name)?.ok_or_else(|| BridgeError::ClassNotFound(name.trim().to_owned()))
    }

    pub const fn as_raw(self) -> usize {
        self.0.get()
    }

    /// Dispatches a class message using only integer/pointer GPR ABI values.
    /// Apple targets convert an Objective-C exception into
    /// [`BridgeError::ObjectiveCException`].
    ///
    /// # Safety
    ///
    /// The selected method's ABI must exactly match the supplied scalar kinds,
    /// machine-word argument convention, and requested return kind.
    pub unsafe fn send(
        self,
        selector: ObjcSelector,
        arguments: &[ScalarValue],
        return_kind: ScalarKind,
    ) -> BridgeResult<ScalarValue> {
        unsafe { dispatch_message(self.as_raw(), selector, arguments, return_kind) }
    }

    /// Reads a class property through its explicit getter selector.
    ///
    /// # Safety
    ///
    /// The getter ABI must match `return_kind` and take no explicit arguments.
    pub unsafe fn read_property(self, getter: ObjcSelector, return_kind: ScalarKind) -> BridgeResult<ScalarValue> {
        unsafe { self.send(getter, &[], return_kind) }
    }

    /// Writes a class property through its explicit setter selector.
    ///
    /// # Safety
    ///
    /// The setter ABI must accept the supplied scalar kind and return void.
    pub unsafe fn write_property(self, setter: ObjcSelector, value: ScalarValue) -> BridgeResult<()> {
        unsafe { self.send(setter, &[value], ScalarKind::Void) }.map(|_| ())
    }

    /// Compatibility alias. Dispatch is exception-contained despite the
    /// historical method name.
    ///
    /// # Safety
    ///
    /// The requirements of [`Self::send`] apply.
    pub unsafe fn send_unchecked_exceptions(
        self,
        selector: ObjcSelector,
        arguments: &[ScalarValue],
        return_kind: ScalarKind,
    ) -> BridgeResult<ScalarValue> {
        unsafe { self.send(selector, arguments, return_kind) }
    }
}

impl fmt::Debug for ObjcClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ObjcClass")
            .field(&format_args!("{:#x}", self.as_raw()))
            .finish()
    }
}

pub struct PendingObjcClass {
    raw: NonZeroUsize,
    name: String,
    registered: bool,
    mutation_failed: bool,
    managed_property_lifecycle_installed: bool,
    added_ivars: Vec<AddedIvar>,
    _not_send_or_sync: PhantomData<Rc<()>>,
}

#[derive(Debug, Clone)]
struct AddedIvar {
    name: String,
    size: usize,
    alignment: usize,
    type_encoding: String,
}

impl PendingObjcClass {
    fn allocate(superclass: ObjcClass, name: &str) -> BridgeResult<Self> {
        let raw = platform::allocate_class_pair(superclass.as_raw(), name)?;
        let raw = NonZeroUsize::new(raw).ok_or_else(|| BridgeError::ClassAllocationFailed(name.to_owned()))?;
        Ok(Self {
            raw,
            name: name.to_owned(),
            registered: false,
            mutation_failed: false,
            managed_property_lifecycle_installed: false,
            added_ivars: Vec::new(),
            _not_send_or_sync: PhantomData,
        })
    }

    pub const fn as_raw(&self) -> usize {
        self.raw.get()
    }

    pub fn add_ivar(&mut self, name: &str, size: usize, alignment: usize, type_encoding: &str) -> BridgeResult<()> {
        let name = checked_name(name, "ivar")?;
        let type_encoding = checked_name(type_encoding, "type encoding")?;
        if size == 0 || alignment == 0 || !alignment.is_power_of_two() {
            return Err(BridgeError::InvalidIvarLayout { size, alignment });
        }
        let alignment_log2 =
            u8::try_from(alignment.trailing_zeros()).map_err(|_| BridgeError::InvalidIvarLayout { size, alignment })?;
        platform::add_ivar(self.as_raw(), &self.name, name, size, alignment_log2, type_encoding).map(|()| {
            self.added_ivars.push(AddedIvar {
                name: name.to_owned(),
                size,
                alignment,
                type_encoding: type_encoding.to_owned(),
            });
        })
    }

    /// Adds a scalar/pointer property with a private backing ivar and runtime
    /// accessors. Object-pointer values use raw assign semantics by default.
    pub fn add_synthesized_property(&mut self, name: &str, type_encoding: &str, read_only: bool) -> BridgeResult<()> {
        self.add_synthesized_property_with_options(
            name,
            type_encoding,
            SynthesizedPropertyOptions::new(read_only, PropertyOwnership::Assign),
        )
    }

    /// Adds a synthesized property with an explicit object ownership policy.
    /// Retain, copy, and weak are valid only for Objective-C object encodings
    /// (`@`).
    pub fn add_synthesized_property_with_ownership(
        &mut self,
        name: &str,
        type_encoding: &str,
        read_only: bool,
        ownership: PropertyOwnership,
    ) -> BridgeResult<()> {
        self.add_synthesized_property_with_options(
            name,
            type_encoding,
            SynthesizedPropertyOptions::new(read_only, ownership),
        )
    }

    /// Adds a synthesized property with optional custom Objective-C getter and
    /// setter selectors. Existing convenience methods use the default
    /// `<name>` and `set<Name>:` selectors.
    pub fn add_synthesized_property_with_options(
        &mut self,
        name: &str,
        type_encoding: &str,
        options: SynthesizedPropertyOptions,
    ) -> BridgeResult<()> {
        let name = checked_property_name(name)?;
        let type_encoding = checked_name(type_encoding, "property type encoding")?;
        let (getter_name, setter_name) = synthesized_property_accessor_names(name, &options)?;
        let layout = synthesized_property_layout(type_encoding)?;
        let normalized_encoding = type_encoding.trim_start_matches(['r', 'n', 'N', 'o', 'O', 'R', 'V']);
        if !matches!(options.ownership, PropertyOwnership::Assign) && !normalized_encoding.starts_with('@') {
            return Err(BridgeError::UnsupportedPropertyOwnership {
                encoding: type_encoding.to_owned(),
                ownership: options.ownership,
            });
        }
        let backing_name = format!("_{name}");
        platform::validate_synthesized_accessors(self.as_raw(), &self.name, &getter_name, setter_name.as_deref())?;

        if let Some(existing) = self.added_ivars.iter().find(|ivar| ivar.name == backing_name) {
            if existing.size != layout.size
                || existing.alignment != layout.alignment
                || existing.type_encoding != type_encoding
            {
                return Err(BridgeError::ClassMutationFailed {
                    class_name: self.name.clone(),
                    member_name: backing_name,
                    operation: "property backing ivar type mismatch",
                });
            }
        } else {
            self.add_ivar(&backing_name, layout.size, layout.alignment, type_encoding)?;
        }

        if options.ownership.requires_managed_lifecycle() && !self.managed_property_lifecycle_installed {
            if let Err(error) = platform::install_managed_property_lifecycle(self.as_raw(), &self.name) {
                self.mutation_failed = true;
                return Err(error);
            }
            self.managed_property_lifecycle_installed = true;
        }

        let result = platform::add_synthesized_property(
            self.as_raw(),
            &self.name,
            name,
            type_encoding,
            &backing_name,
            options.read_only,
            options.ownership,
            options.atomic,
            &getter_name,
            setter_name.as_deref(),
        );
        if result.is_err() {
            self.mutation_failed = true;
            return result;
        }
        if matches!(options.kvo, PropertyKvo::Manual) {
            if let Err(error) = platform::install_manual_kvo(self.as_raw(), &self.name, name) {
                self.mutation_failed = true;
                return Err(error);
            }
        }
        Ok(())
    }

    /// Adds an instance method before registration.
    ///
    /// # Safety
    ///
    /// `implementation` must remain executable for the process lifetime and
    /// exactly match the selector and Objective-C type encoding ABI.
    pub unsafe fn add_method(
        &mut self,
        selector: ObjcSelector,
        implementation: usize,
        type_encoding: &str,
    ) -> BridgeResult<()> {
        self.add_method_to(false, selector, implementation, type_encoding)
    }

    /// Adds a class method to the pending metaclass.
    ///
    /// # Safety
    ///
    /// The same ABI and lifetime requirements as [`Self::add_method`] apply.
    pub unsafe fn add_class_method(
        &mut self,
        selector: ObjcSelector,
        implementation: usize,
        type_encoding: &str,
    ) -> BridgeResult<()> {
        self.add_method_to(true, selector, implementation, type_encoding)
    }

    fn add_method_to(
        &mut self,
        class_method: bool,
        selector: ObjcSelector,
        implementation: usize,
        type_encoding: &str,
    ) -> BridgeResult<()> {
        if implementation == 0 {
            return Err(BridgeError::NullImplementation);
        }
        let type_encoding = checked_name(type_encoding, "type encoding")?;
        platform::add_method(
            self.as_raw(),
            &self.name,
            class_method,
            selector.as_raw(),
            implementation,
            type_encoding,
        )
    }

    pub fn register(mut self) -> BridgeResult<ObjcClass> {
        if self.mutation_failed {
            return Err(BridgeError::ClassMutationFailed {
                class_name: self.name.clone(),
                member_name: self.name.clone(),
                operation: "registration after a failed property mutation",
            });
        }
        platform::register_class_pair(self.as_raw())?;
        self.registered = true;
        Ok(ObjcClass(self.raw))
    }
}

impl fmt::Debug for PendingObjcClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingObjcClass")
            .field("raw", &format_args!("{:#x}", self.as_raw()))
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl Drop for PendingObjcClass {
    fn drop(&mut self) {
        if !self.registered {
            unsafe { platform::dispose_class_pair(self.as_raw()) };
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObjcSelector(NonZeroUsize);

impl ObjcSelector {
    pub fn register(name: &str) -> BridgeResult<Self> {
        let name = checked_name(name, "selector")?;
        let raw = platform::register_selector(name)?;
        NonZeroUsize::new(raw).map(Self).ok_or(BridgeError::InvalidName {
            kind: "selector",
            reason: "runtime returned null",
        })
    }

    pub const fn as_raw(self) -> usize {
        self.0.get()
    }
}

impl fmt::Debug for ObjcSelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ObjcSelector")
            .field(&format_args!("{:#x}", self.as_raw()))
            .finish()
    }
}

pub struct ObjcObject {
    raw: NonZeroUsize,
    _not_send_or_sync: PhantomData<Rc<()>>,
}

impl ObjcObject {
    /// Retains a trusted live object pointer.
    ///
    /// # Safety
    ///
    /// See [`ObjectBridge::retain_object`].
    pub unsafe fn retain_raw(raw: usize) -> BridgeResult<Self> {
        platform::validate_object(raw)?;
        let retained = unsafe { platform::retain(raw)? };
        let raw = NonZeroUsize::new(retained).ok_or(BridgeError::NullPointer)?;
        Ok(Self {
            raw,
            _not_send_or_sync: PhantomData,
        })
    }

    /// Adopts a trusted +1 object pointer without retaining it again.
    ///
    /// # Safety
    ///
    /// See [`ObjectBridge::adopt_retained_object`].
    pub unsafe fn from_retained_raw(raw: usize) -> BridgeResult<Self> {
        platform::validate_object(raw)?;
        let raw = NonZeroUsize::new(raw).ok_or(BridgeError::NullPointer)?;
        Ok(Self {
            raw,
            _not_send_or_sync: PhantomData,
        })
    }

    pub const fn as_raw(&self) -> usize {
        self.raw.get()
    }

    pub fn try_clone(&self) -> BridgeResult<Self> {
        let retained = unsafe { platform::retain(self.as_raw())? };
        let raw = NonZeroUsize::new(retained).ok_or(BridgeError::NullPointer)?;
        Ok(Self {
            raw,
            _not_send_or_sync: PhantomData,
        })
    }

    pub fn into_raw(self) -> usize {
        let this = ManuallyDrop::new(self);
        this.as_raw()
    }

    pub fn try_release(self) -> BridgeResult<()> {
        let this = ManuallyDrop::new(self);
        unsafe { platform::release(this.as_raw()) }
    }

    pub fn release(self) {
        let _ = self.try_release();
    }

    /// Dispatches an instance message using only integer/pointer GPR ABI
    /// values. Apple targets convert an Objective-C exception into
    /// [`BridgeError::ObjectiveCException`].
    ///
    /// # Safety
    ///
    /// The selected method's ABI must exactly match the supplied scalar kinds,
    /// machine-word argument convention, and requested return kind. Object
    /// pointer return values remain borrowed raw pointers until explicitly
    /// retained or adopted with the correct ownership convention.
    pub unsafe fn send(
        &self,
        selector: ObjcSelector,
        arguments: &[ScalarValue],
        return_kind: ScalarKind,
    ) -> BridgeResult<ScalarValue> {
        unsafe { dispatch_message(self.as_raw(), selector, arguments, return_kind) }
    }

    /// Reads a property through its explicit getter selector.
    ///
    /// # Safety
    ///
    /// The getter ABI must match `return_kind` and take no explicit arguments.
    pub unsafe fn read_property(&self, getter: ObjcSelector, return_kind: ScalarKind) -> BridgeResult<ScalarValue> {
        unsafe { self.send(getter, &[], return_kind) }
    }

    /// Writes a property through its explicit setter selector.
    ///
    /// # Safety
    ///
    /// The setter ABI must accept the supplied scalar kind and return void.
    pub unsafe fn write_property(&self, setter: ObjcSelector, value: ScalarValue) -> BridgeResult<()> {
        unsafe { self.send(setter, &[value], ScalarKind::Void) }.map(|_| ())
    }

    /// Compatibility alias. Dispatch is exception-contained despite the
    /// historical method name.
    ///
    /// # Safety
    ///
    /// The requirements of [`Self::send`] apply.
    pub unsafe fn send_unchecked_exceptions(
        &self,
        selector: ObjcSelector,
        arguments: &[ScalarValue],
        return_kind: ScalarKind,
    ) -> BridgeResult<ScalarValue> {
        unsafe { self.send(selector, arguments, return_kind) }
    }

    pub fn ivar_address(&self, name: &str, width: usize, access: IvarAccess) -> BridgeResult<IvarSlot> {
        let name = checked_name(name, "ivar")?;
        if width == 0 {
            return Err(BridgeError::InvalidMemoryRange {
                address: self.as_raw(),
                length: 0,
                reason: "ivar width must be non-zero".into(),
            });
        }
        platform::resolve_ivar(self.as_raw(), name, width, access)
    }

    /// Reads a bounded scalar or pointer directly from an ivar slot.
    ///
    /// This is raw storage access; it does not invoke property accessors.
    pub fn read_ivar(&self, name: &str, kind: ScalarKind) -> BridgeResult<ScalarValue> {
        let width = kind.width().ok_or_else(|| BridgeError::InvalidMemoryRange {
            address: self.as_raw(),
            length: 0,
            reason: "void has no ivar storage width".into(),
        })?;
        let slot = self.ivar_address(name, width, IvarAccess::Read)?;
        validate_ivar_kind(name, kind, slot.type_encoding.as_deref())?;
        unsafe { platform::read_scalar(slot.address, kind) }
    }

    /// Writes a bounded scalar or pointer directly into an ivar slot.
    ///
    /// Pointer writes do not perform strong/weak ownership operations, ARC
    /// barriers, KVO notifications, or property setter calls.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the value kind matches the ivar's runtime
    /// type encoding and that raw pointer ownership semantics are appropriate.
    pub unsafe fn write_ivar(&self, name: &str, value: ScalarValue) -> BridgeResult<()> {
        let kind = value.kind();
        let width = kind.width().ok_or_else(|| BridgeError::InvalidMemoryRange {
            address: self.as_raw(),
            length: 0,
            reason: "void has no ivar storage width".into(),
        })?;
        let slot = self.ivar_address(name, width, IvarAccess::Write)?;
        validate_ivar_kind(name, kind, slot.type_encoding.as_deref())?;
        unsafe { platform::write_scalar(slot.address, value) }
    }
}

impl fmt::Debug for ObjcObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObjcObject")
            .field("raw", &format_args!("{:#x}", self.as_raw()))
            .finish_non_exhaustive()
    }
}

impl Drop for ObjcObject {
    fn drop(&mut self) {
        let _ = unsafe { platform::release(self.as_raw()) };
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IvarAccess {
    Read,
    Write,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IvarSlot {
    pub address: usize,
    pub offset: usize,
    pub width: usize,
    pub type_encoding: Option<String>,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScalarKind {
    Void = 0,
    Bool = 1,
    I8 = 2,
    U8 = 3,
    I16 = 4,
    U16 = 5,
    I32 = 6,
    U32 = 7,
    I64 = 8,
    U64 = 9,
    Isize = 10,
    Usize = 11,
    Pointer = 12,
}

impl ScalarKind {
    pub const fn width(self) -> Option<usize> {
        match self {
            Self::Void => None,
            Self::Bool | Self::I8 | Self::U8 => Some(1),
            Self::I16 | Self::U16 => Some(2),
            Self::I32 | Self::U32 => Some(4),
            Self::I64 | Self::U64 => Some(8),
            Self::Isize | Self::Usize | Self::Pointer => Some(std::mem::size_of::<usize>()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScalarValue {
    Void,
    Bool(bool),
    I8(i8),
    U8(u8),
    I16(i16),
    U16(u16),
    I32(i32),
    U32(u32),
    I64(i64),
    U64(u64),
    Isize(isize),
    Usize(usize),
    Pointer(usize),
}

impl ScalarValue {
    pub const fn kind(self) -> ScalarKind {
        match self {
            Self::Void => ScalarKind::Void,
            Self::Bool(_) => ScalarKind::Bool,
            Self::I8(_) => ScalarKind::I8,
            Self::U8(_) => ScalarKind::U8,
            Self::I16(_) => ScalarKind::I16,
            Self::U16(_) => ScalarKind::U16,
            Self::I32(_) => ScalarKind::I32,
            Self::U32(_) => ScalarKind::U32,
            Self::I64(_) => ScalarKind::I64,
            Self::U64(_) => ScalarKind::U64,
            Self::Isize(_) => ScalarKind::Isize,
            Self::Usize(_) => ScalarKind::Usize,
            Self::Pointer(_) => ScalarKind::Pointer,
        }
    }

    fn to_argument_word(self) -> BridgeResult<usize> {
        match self {
            Self::Void => unreachable!("void arguments are rejected before conversion"),
            Self::Bool(value) => Ok(usize::from(value)),
            Self::I8(value) => Ok(value as isize as usize),
            Self::U8(value) => Ok(value as usize),
            Self::I16(value) => Ok(value as isize as usize),
            Self::U16(value) => Ok(value as usize),
            Self::I32(value) => Ok(value as isize as usize),
            Self::U32(value) => Ok(value as usize),
            Self::I64(value) => isize::try_from(value)
                .map(|value| value as usize)
                .map_err(|_| BridgeError::ValueOutOfRange { kind: ScalarKind::I64 }),
            Self::U64(value) => {
                usize::try_from(value).map_err(|_| BridgeError::ValueOutOfRange { kind: ScalarKind::U64 })
            }
            Self::Isize(value) => Ok(value as usize),
            Self::Usize(value) | Self::Pointer(value) => Ok(value),
        }
    }

    #[cfg(any(target_os = "ios", target_os = "macos", test))]
    fn from_return_word(kind: ScalarKind, word: usize) -> Self {
        match kind {
            ScalarKind::Void => Self::Void,
            ScalarKind::Bool => Self::Bool(word != 0),
            ScalarKind::I8 => Self::I8(word as i8),
            ScalarKind::U8 => Self::U8(word as u8),
            ScalarKind::I16 => Self::I16(word as i16),
            ScalarKind::U16 => Self::U16(word as u16),
            ScalarKind::I32 => Self::I32(word as i32),
            ScalarKind::U32 => Self::U32(word as u32),
            ScalarKind::I64 => Self::I64(word as i64),
            ScalarKind::U64 => Self::U64(word as u64),
            ScalarKind::Isize => Self::Isize(word as isize),
            ScalarKind::Usize => Self::Usize(word),
            ScalarKind::Pointer => Self::Pointer(word),
        }
    }
}

fn checked_name<'a>(name: &'a str, kind: &'static str) -> BridgeResult<&'a str> {
    let name = name.trim();
    if name.is_empty() {
        return Err(BridgeError::InvalidName {
            kind,
            reason: "name must not be empty",
        });
    }
    if name.as_bytes().contains(&0) {
        return Err(BridgeError::InvalidName {
            kind,
            reason: "name contains an interior NUL byte",
        });
    }
    Ok(name)
}

fn checked_property_name(name: &str) -> BridgeResult<&str> {
    let name = checked_name(name, "property")?;
    if name.len() > MAX_SYNTHESIZED_PROPERTY_NAME_LENGTH {
        return Err(BridgeError::InvalidName {
            kind: "property",
            reason: "name exceeds 255 bytes",
        });
    }
    let mut characters = name.chars();
    let valid_first = characters
        .next()
        .map(|character| character == '_' || character.is_ascii_alphabetic())
        .unwrap_or(false);
    let valid_rest = characters.all(|character| character == '_' || character.is_ascii_alphanumeric());
    if !valid_first || !valid_rest {
        return Err(BridgeError::InvalidName {
            kind: "property",
            reason: "name must be an ASCII identifier without ':' or whitespace",
        });
    }
    Ok(name)
}

fn checked_property_getter(name: &str) -> BridgeResult<&str> {
    let name = checked_name(name, "property getter")?;
    if name.contains(':') {
        return Err(BridgeError::InvalidName {
            kind: "property getter",
            reason: "getter selector must not contain ':'",
        });
    }
    if name.contains(',') {
        return Err(BridgeError::InvalidName {
            kind: "property getter",
            reason: "getter selector must not contain ','",
        });
    }
    Ok(name)
}

fn checked_property_setter(name: &str) -> BridgeResult<&str> {
    let name = checked_name(name, "property setter")?;
    if name == ":" || !name.ends_with(':') || name[..name.len() - 1].contains(':') {
        return Err(BridgeError::InvalidName {
            kind: "property setter",
            reason: "setter selector must contain exactly one trailing ':'",
        });
    }
    if name.contains(',') {
        return Err(BridgeError::InvalidName {
            kind: "property setter",
            reason: "setter selector must not contain ','",
        });
    }
    Ok(name)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SynthesizedPropertyLayout {
    size: usize,
    alignment: usize,
}

fn synthesized_property_layout(type_encoding: &str) -> BridgeResult<SynthesizedPropertyLayout> {
    let encoding = checked_name(type_encoding, "property type encoding")?;
    let encoding = encoding.trim_start_matches(['r', 'n', 'N', 'o', 'O', 'R', 'V']);
    let kind = synthesized_property_kind(encoding).ok_or_else(|| BridgeError::UnsupportedPropertyType {
        encoding: type_encoding.to_owned(),
    })?;
    let size = kind.width().expect("synthesized property kind is never void");
    Ok(SynthesizedPropertyLayout { size, alignment: size })
}

fn synthesized_property_kind(type_encoding: &str) -> Option<ScalarKind> {
    let type_encoding = type_encoding
        .trim()
        .trim_start_matches(['r', 'n', 'N', 'o', 'O', 'R', 'V']);
    match type_encoding.as_bytes().first().copied() {
        Some(b'B') => Some(ScalarKind::Bool),
        Some(b'c') => Some(ScalarKind::I8),
        Some(b'C') => Some(ScalarKind::U8),
        Some(b's') => Some(ScalarKind::I16),
        Some(b'S') => Some(ScalarKind::U16),
        Some(b'i') => Some(ScalarKind::I32),
        Some(b'I') => Some(ScalarKind::U32),
        Some(b'l') => Some(ScalarKind::Isize),
        Some(b'L') => Some(ScalarKind::Usize),
        Some(b'q') => Some(ScalarKind::I64),
        Some(b'Q') => Some(ScalarKind::U64),
        Some(b'@' | b'#' | b':' | b'^' | b'*') => Some(ScalarKind::Pointer),
        _ => None,
    }
}

fn property_setter_name(property_name: &str) -> String {
    let mut characters = property_name.chars();
    let first = characters.next().expect("validated non-empty property name");
    let uppercase = first.to_uppercase().collect::<String>();
    format!("set{uppercase}{}:", characters.as_str())
}

fn synthesized_property_accessor_names(
    property_name: &str,
    options: &SynthesizedPropertyOptions,
) -> BridgeResult<(String, Option<String>)> {
    let getter = match options.getter.as_deref() {
        Some(getter) => checked_property_getter(getter)?.to_owned(),
        None => property_name.to_owned(),
    };
    if options.read_only && options.setter.is_some() {
        return Err(BridgeError::InvalidName {
            kind: "property setter",
            reason: "read-only properties must not declare a setter",
        });
    }
    if options.read_only && matches!(options.kvo, PropertyKvo::Manual) {
        return Err(BridgeError::InvalidName {
            kind: "property KVO mode",
            reason: "manual KVO requires a writable property setter",
        });
    }
    let setter = if options.read_only {
        None
    } else {
        Some(match options.setter.as_deref() {
            Some(setter) => checked_property_setter(setter)?.to_owned(),
            None => property_setter_name(property_name),
        })
    };
    Ok((getter, setter))
}

fn checked_object_address(raw: usize) -> BridgeResult<()> {
    if raw == 0 {
        return Err(BridgeError::NullPointer);
    }
    let alignment = std::mem::align_of::<usize>();
    if !raw.is_multiple_of(alignment) {
        return Err(BridgeError::MisalignedObjectPointer {
            address: raw,
            alignment,
        });
    }
    Ok(())
}

fn checked_arguments(arguments: &[ScalarValue]) -> BridgeResult<Vec<usize>> {
    if arguments.len() > MAX_MESSAGE_ARGUMENTS {
        return Err(BridgeError::TooManyArguments {
            supplied: arguments.len(),
            maximum: MAX_MESSAGE_ARGUMENTS,
        });
    }
    arguments
        .iter()
        .copied()
        .enumerate()
        .map(|(index, value)| {
            if value == ScalarValue::Void {
                return Err(BridgeError::VoidArgument { index });
            }
            value.to_argument_word()
        })
        .collect()
}

fn validate_ivar_kind(name: &str, requested: ScalarKind, encoding: Option<&str>) -> BridgeResult<()> {
    let encoding = encoding.unwrap_or("<missing>");
    let bare = encoding.trim_start_matches(['r', 'n', 'N', 'o', 'O', 'R', 'V']);
    let compatible = match requested {
        ScalarKind::Void => false,
        ScalarKind::Bool => bare.starts_with('B'),
        ScalarKind::I8 => bare.starts_with('c'),
        ScalarKind::U8 => bare.starts_with('C'),
        ScalarKind::I16 => bare.starts_with('s'),
        ScalarKind::U16 => bare.starts_with('S'),
        ScalarKind::I32 => bare.starts_with('i'),
        ScalarKind::U32 => bare.starts_with('I'),
        ScalarKind::I64 | ScalarKind::Isize => bare.starts_with('q'),
        ScalarKind::U64 | ScalarKind::Usize => bare.starts_with('Q'),
        ScalarKind::Pointer => matches!(bare.as_bytes().first(), Some(b'@' | b'#' | b':' | b'*' | b'^')),
    };
    if compatible {
        Ok(())
    } else {
        Err(BridgeError::IvarTypeMismatch {
            name: name.to_owned(),
            requested,
            encoding: encoding.to_owned(),
        })
    }
}

unsafe fn dispatch_message(
    receiver: usize,
    selector: ObjcSelector,
    arguments: &[ScalarValue],
    return_kind: ScalarKind,
) -> BridgeResult<ScalarValue> {
    let words = checked_arguments(arguments)?;
    unsafe { platform::dispatch(receiver, selector.as_raw(), &words, return_kind) }
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
mod platform {
    use super::{
        checked_object_address, BridgeError, BridgeResult, IvarAccess, IvarSlot, ObjcException, PropertyOwnership,
        ScalarKind, ScalarValue,
    };
    use std::ffi::{CStr, CString};
    use std::mem;
    use std::os::raw::{c_char, c_void};

    const VM_PROT_READ: libc::vm_prot_t = 1;
    const VM_PROT_WRITE: libc::vm_prot_t = 2;

    #[repr(C)]
    struct RawExceptionInfo {
        name: [c_char; 128],
        reason: [c_char; 512],
    }

    impl Default for RawExceptionInfo {
        fn default() -> Self {
            Self {
                name: [0; 128],
                reason: [0; 512],
            }
        }
    }

    struct ResolvedSynthesizedProperty {
        slot: usize,
        kind: ScalarKind,
        ownership: PropertyOwnership,
        atomic: bool,
        manual_kvo_key: Option<String>,
    }

    #[repr(C, packed(4))]
    #[derive(Default)]
    struct VmRegionSubmapInfo64 {
        protection: libc::vm_prot_t,
        max_protection: libc::vm_prot_t,
        inheritance: libc::vm_inherit_t,
        offset: libc::memory_object_offset_t,
        user_tag: libc::c_uint,
        pages_resident: libc::c_uint,
        pages_shared_now_private: libc::c_uint,
        pages_swapped_out: libc::c_uint,
        pages_dirtied: libc::c_uint,
        ref_count: libc::c_uint,
        shadow_depth: libc::c_ushort,
        external_pager: libc::c_uchar,
        share_mode: libc::c_uchar,
        is_submap: libc::boolean_t,
        behavior: libc::c_int,
        object_id: libc::c_uint,
        user_wired_count: libc::c_ushort,
        flags: libc::c_ushort,
        pages_reusable: libc::c_uint,
        object_id_full: u64,
    }

    const VM_REGION_SUBMAP_INFO_COUNT_64: libc::mach_msg_type_number_t =
        (mem::size_of::<VmRegionSubmapInfo64>() / mem::size_of::<libc::natural_t>()) as libc::mach_msg_type_number_t;

    #[link(name = "objc")]
    extern "C" {
        fn objc_lookUpClass(name: *const c_char) -> *mut c_void;
        fn sel_registerName(name: *const c_char) -> *const c_void;
        fn object_getClass(object: *const c_void) -> *mut c_void;
        fn class_getSuperclass(class: *const c_void) -> *mut c_void;
        fn class_getInstanceSize(class: *const c_void) -> usize;
        fn class_getInstanceVariable(class: *const c_void, name: *const c_char) -> *mut c_void;
        fn class_copyMethodList(class: *const c_void, count: *mut u32) -> *mut *mut c_void;
        fn method_getName(method: *const c_void) -> *const c_void;
        fn ivar_getOffset(ivar: *const c_void) -> isize;
        fn ivar_getTypeEncoding(ivar: *const c_void) -> *const c_char;
        fn objc_allocateClassPair(superclass: *const c_void, name: *const c_char, extra_bytes: usize) -> *mut c_void;
        fn objc_registerClassPair(class: *mut c_void);
        fn objc_disposeClassPair(class: *mut c_void);
        fn class_addIvar(
            class: *mut c_void,
            name: *const c_char,
            size: usize,
            alignment: u8,
            types: *const c_char,
        ) -> bool;
        fn class_addMethod(
            class: *mut c_void,
            selector: *const c_void,
            implementation: *const c_void,
            types: *const c_char,
        ) -> bool;
        fn class_addProperty(
            class: *mut c_void,
            name: *const c_char,
            attributes: *const ObjcPropertyAttribute,
            count: u32,
        ) -> bool;
        fn class_copyPropertyList(class: *const c_void, count: *mut u32) -> *mut *mut c_void;
        fn property_getName(property: *const c_void) -> *const c_char;
        fn property_getAttributes(property: *const c_void) -> *const c_char;
        fn property_copyAttributeValue(property: *const c_void, attribute_name: *const c_char) -> *mut c_char;
        fn sel_getName(selector: *const c_void) -> *const c_char;
    }

    #[repr(C)]
    struct ObjcPropertyAttribute {
        name: *const c_char,
        value: *const c_char,
    }

    extern "C" {
        fn rf_objc_try_msg_send(
            receiver: *mut c_void,
            selector: *const c_void,
            arguments: *const usize,
            argument_count: usize,
            return_kind: u32,
            result: *mut usize,
            exception_info: *mut RawExceptionInfo,
        ) -> i32;
        fn rf_objc_try_retain(
            object: *mut c_void,
            result: *mut *mut c_void,
            exception_info: *mut RawExceptionInfo,
        ) -> i32;
        fn rf_objc_try_copy(
            object: *mut c_void,
            result: *mut *mut c_void,
            exception_info: *mut RawExceptionInfo,
        ) -> i32;
        fn rf_objc_try_release(object: *mut c_void, exception_info: *mut RawExceptionInfo) -> i32;
        fn rf_objc_try_store_weak(
            location: *mut *mut c_void,
            object: *mut c_void,
            exception_info: *mut RawExceptionInfo,
        ) -> i32;
        fn rf_objc_try_load_weak(
            location: *mut *mut c_void,
            result: *mut *mut c_void,
            exception_info: *mut RawExceptionInfo,
        ) -> i32;
        fn rf_objc_try_atomic_get_object(
            object: *mut c_void,
            selector: *const c_void,
            offset: isize,
            result: *mut *mut c_void,
            exception_info: *mut RawExceptionInfo,
        ) -> i32;
        fn rf_objc_try_atomic_set_object(
            object: *mut c_void,
            selector: *const c_void,
            offset: isize,
            value: *mut c_void,
            should_copy: bool,
            exception_info: *mut RawExceptionInfo,
        ) -> i32;
        fn rf_objc_try_atomic_load_value(
            location: *const c_void,
            result: *mut c_void,
            size: usize,
            exception_info: *mut RawExceptionInfo,
        ) -> i32;
        fn rf_objc_try_atomic_store_value(
            location: *mut c_void,
            value: *const c_void,
            size: usize,
            exception_info: *mut RawExceptionInfo,
        ) -> i32;
        fn rf_objc_install_manual_kvo(class: *mut c_void, property_name: *const c_char) -> i32;
        fn rf_objc_property_uses_manual_kvo(class: *mut c_void, property_name: *const c_char) -> i32;
        fn rf_objc_try_kvo_will_change(
            object: *mut c_void,
            property_name: *const c_char,
            exception_info: *mut RawExceptionInfo,
        ) -> i32;
        fn rf_objc_try_kvo_did_change(
            object: *mut c_void,
            property_name: *const c_char,
            exception_info: *mut RawExceptionInfo,
        ) -> i32;
        fn rf_objc_install_managed_property_lifecycle(class: *mut c_void) -> i32;
    }

    extern "C" {
        static mach_task_self_: libc::mach_port_t;

        fn mach_vm_region_recurse(
            target_task: libc::vm_map_t,
            address: *mut libc::mach_vm_address_t,
            size: *mut libc::mach_vm_size_t,
            nesting_depth: *mut libc::natural_t,
            info: *mut libc::integer_t,
            info_count: *mut libc::mach_msg_type_number_t,
        ) -> libc::kern_return_t;
    }

    pub fn lookup_class(name: &str) -> BridgeResult<Option<usize>> {
        let name = CString::new(name).expect("checked class name");
        let raw = unsafe { objc_lookUpClass(name.as_ptr()) } as usize;
        if raw == 0 {
            return Ok(None);
        }
        validate_range(raw, mem::size_of::<usize>(), IvarAccess::Read)?;
        Ok(Some(raw))
    }

    pub fn register_selector(name: &str) -> BridgeResult<usize> {
        let name = CString::new(name).expect("checked selector name");
        let raw = unsafe { sel_registerName(name.as_ptr()) } as usize;
        if raw != 0 {
            validate_range(raw, 1, IvarAccess::Read)?;
        }
        Ok(raw)
    }

    pub fn allocate_class_pair(superclass: usize, name: &str) -> BridgeResult<usize> {
        let name_c = CString::new(name).expect("checked class name");
        let raw = unsafe { objc_allocateClassPair(superclass as *const c_void, name_c.as_ptr(), 0) } as usize;
        if raw == 0 {
            Err(BridgeError::ClassAllocationFailed(name.to_owned()))
        } else {
            Ok(raw)
        }
    }

    pub fn add_ivar(
        class: usize,
        class_name: &str,
        name: &str,
        size: usize,
        alignment_log2: u8,
        type_encoding: &str,
    ) -> BridgeResult<()> {
        let name_c = CString::new(name).expect("checked ivar name");
        let type_encoding_c = CString::new(type_encoding).expect("checked type encoding");
        let added = unsafe {
            class_addIvar(
                class as *mut c_void,
                name_c.as_ptr(),
                size,
                alignment_log2,
                type_encoding_c.as_ptr(),
            )
        };
        if added {
            Ok(())
        } else {
            Err(BridgeError::ClassMutationFailed {
                class_name: class_name.to_owned(),
                member_name: name.to_owned(),
                operation: "ivar addition",
            })
        }
    }

    pub fn validate_synthesized_accessors(
        class: usize,
        class_name: &str,
        getter_name: &str,
        setter_name: Option<&str>,
    ) -> BridgeResult<()> {
        for selector_name in std::iter::once(getter_name).chain(setter_name) {
            let selector_name_c = CString::new(selector_name).expect("checked property accessor");
            let selector = unsafe { sel_registerName(selector_name_c.as_ptr()) };
            if selector.is_null() {
                return Err(BridgeError::InvalidName {
                    kind: "property accessor",
                    reason: "runtime returned null selector",
                });
            }
            let mut current_class = class as *mut c_void;
            while !current_class.is_null() {
                let mut method_count = 0;
                let methods = unsafe { class_copyMethodList(current_class, &mut method_count) };
                let method_slice = if methods.is_null() {
                    &[][..]
                } else {
                    unsafe { std::slice::from_raw_parts(methods, method_count as usize) }
                };
                let collides = method_slice
                    .iter()
                    .any(|&method| unsafe { method_getName(method) } == selector);
                unsafe { libc::free(methods.cast()) };
                if collides {
                    return Err(BridgeError::ClassMutationFailed {
                        class_name: class_name.to_owned(),
                        member_name: selector_name.to_owned(),
                        operation: "property accessor selector collision",
                    });
                }
                current_class = unsafe { class_getSuperclass(current_class) };
            }
        }
        Ok(())
    }

    pub fn add_synthesized_property(
        class: usize,
        class_name: &str,
        name: &str,
        type_encoding: &str,
        backing_name: &str,
        read_only: bool,
        ownership: PropertyOwnership,
        atomic: bool,
        getter_name: &str,
        setter_name: Option<&str>,
    ) -> BridgeResult<()> {
        let name_c = CString::new(name).expect("checked property name");
        let type_value = CString::new(type_encoding).expect("checked property type encoding");
        let backing_value = CString::new(backing_name).expect("checked backing ivar name");
        let getter_value = CString::new(getter_name).expect("checked property getter");
        let setter_value = setter_name.map(|setter| CString::new(setter).expect("checked property setter"));
        let attr_t = CString::new("T").expect("literal");
        let attr_v = CString::new("V").expect("literal");
        let attr_n = CString::new("N").expect("literal");
        let attr_ro = CString::new("R").expect("literal");
        let attr_getter = CString::new("G").expect("literal");
        let attr_setter = CString::new("S").expect("literal");
        let attr_retain = CString::new("&").expect("literal");
        let attr_copy = CString::new("C").expect("literal");
        let attr_weak = CString::new("W").expect("literal");
        let empty = CString::new("").expect("literal");
        let mut attrs = vec![
            ObjcPropertyAttribute {
                name: attr_t.as_ptr(),
                value: type_value.as_ptr(),
            },
            ObjcPropertyAttribute {
                name: attr_v.as_ptr(),
                value: backing_value.as_ptr(),
            },
        ];
        if !atomic {
            attrs.push(ObjcPropertyAttribute {
                name: attr_n.as_ptr(),
                value: empty.as_ptr(),
            });
        }
        match ownership {
            PropertyOwnership::Assign => {}
            PropertyOwnership::Retain => attrs.push(ObjcPropertyAttribute {
                name: attr_retain.as_ptr(),
                value: empty.as_ptr(),
            }),
            PropertyOwnership::Copy => attrs.push(ObjcPropertyAttribute {
                name: attr_copy.as_ptr(),
                value: empty.as_ptr(),
            }),
            PropertyOwnership::Weak => attrs.push(ObjcPropertyAttribute {
                name: attr_weak.as_ptr(),
                value: empty.as_ptr(),
            }),
        }
        if getter_name != name {
            attrs.push(ObjcPropertyAttribute {
                name: attr_getter.as_ptr(),
                value: getter_value.as_ptr(),
            });
        }
        let default_setter = super::property_setter_name(name);
        if let Some(setter_value) = setter_value
            .as_ref()
            .filter(|_| setter_name != Some(default_setter.as_str()))
        {
            attrs.push(ObjcPropertyAttribute {
                name: attr_setter.as_ptr(),
                value: setter_value.as_ptr(),
            });
        }
        if read_only {
            attrs.push(ObjcPropertyAttribute {
                name: attr_ro.as_ptr(),
                value: empty.as_ptr(),
            });
        }
        let added = unsafe {
            class_addProperty(
                class as *mut c_void,
                name_c.as_ptr(),
                attrs.as_ptr(),
                attrs.len() as u32,
            )
        };
        if !added {
            return Err(BridgeError::ClassMutationFailed {
                class_name: class_name.to_owned(),
                member_name: name.to_owned(),
                operation: "property addition",
            });
        }

        let getter = super::ObjcSelector::register(getter_name)?;
        let getter_types = CString::new(format!("{type_encoding}@:")).expect("checked getter type encoding");
        let getter_added = unsafe {
            class_addMethod(
                class as *mut c_void,
                getter.as_raw() as *const c_void,
                synthesized_getter as *const c_void,
                getter_types.as_ptr(),
            )
        };
        if !getter_added {
            return Err(BridgeError::ClassMutationFailed {
                class_name: class_name.to_owned(),
                member_name: getter_name.to_owned(),
                operation: "property getter synthesis",
            });
        }

        if let Some(setter_name) = setter_name {
            let setter = super::ObjcSelector::register(&setter_name)?;
            let setter_types = CString::new(format!("v@:{type_encoding}")).expect("checked setter type encoding");
            let setter_added = unsafe {
                class_addMethod(
                    class as *mut c_void,
                    setter.as_raw() as *const c_void,
                    synthesized_setter as *const c_void,
                    setter_types.as_ptr(),
                )
            };
            if !setter_added {
                return Err(BridgeError::ClassMutationFailed {
                    class_name: class_name.to_owned(),
                    member_name: setter_name.to_owned(),
                    operation: "property setter synthesis",
                });
            }
        }
        Ok(())
    }

    unsafe extern "C" fn synthesized_getter(object: *mut c_void, selector: *const c_void) -> usize {
        let Some(property) = synthesized_slot(object, selector, false) else {
            return 0;
        };
        if property.kind == ScalarKind::Pointer && matches!(property.ownership, PropertyOwnership::Weak) {
            return unsafe { load_synthesized_weak(property.slot) }.unwrap_or(0);
        }
        if property.atomic {
            if property.kind == ScalarKind::Pointer
                && matches!(property.ownership, PropertyOwnership::Retain | PropertyOwnership::Copy)
            {
                return unsafe { load_atomic_synthesized_object(object, selector, property.slot) }.unwrap_or(0);
            }
            return unsafe { load_atomic_synthesized_value(property.slot, property.kind) }.unwrap_or(0);
        }
        unsafe { read_synthesized_value(property.slot, property.kind) }
    }

    unsafe extern "C" fn synthesized_setter(object: *mut c_void, selector: *const c_void, value: usize) {
        let Some(property) = synthesized_slot(object, selector, true) else {
            return;
        };
        if let Some(key) = property.manual_kvo_key.as_deref() {
            if !unsafe { notify_manual_kvo(object, key, true) } {
                return;
            }
        }
        unsafe { write_synthesized_property(object, selector, &property, value) };
        if let Some(key) = property.manual_kvo_key.as_deref() {
            let _ = unsafe { notify_manual_kvo(object, key, false) };
        }
    }

    unsafe fn write_synthesized_property(
        object: *mut c_void,
        selector: *const c_void,
        property: &ResolvedSynthesizedProperty,
        value: usize,
    ) {
        if property.kind == ScalarKind::Pointer && matches!(property.ownership, PropertyOwnership::Weak) {
            let incoming = value as *mut c_void;
            let _ = unsafe { store_synthesized_weak(property.slot, incoming) };
            return;
        }
        if property.atomic {
            if property.kind == ScalarKind::Pointer
                && matches!(property.ownership, PropertyOwnership::Retain | PropertyOwnership::Copy)
            {
                let _ = unsafe {
                    store_atomic_synthesized_object(
                        object,
                        selector,
                        property.slot,
                        value as *mut c_void,
                        matches!(property.ownership, PropertyOwnership::Copy),
                    )
                };
            } else {
                let _ = unsafe { store_atomic_synthesized_value(property.slot, property.kind, value) };
            }
            return;
        }
        if property.kind == ScalarKind::Pointer && !matches!(property.ownership, PropertyOwnership::Assign) {
            let incoming = value as *mut c_void;
            let acquired = match property.ownership {
                PropertyOwnership::Assign => Some(0),
                PropertyOwnership::Retain => unsafe { retain_synthesized_object(incoming) },
                PropertyOwnership::Copy => unsafe { copy_synthesized_object(incoming) },
                PropertyOwnership::Weak => unreachable!("weak ownership returned above"),
            };
            let Some(acquired) = acquired else {
                return;
            };
            let previous = unsafe { read_synthesized_value(property.slot, ScalarKind::Pointer) };
            unsafe { write_synthesized_value(property.slot, ScalarKind::Pointer, acquired) };
            if previous != 0 {
                unsafe { release_synthesized_object(previous as *mut c_void) };
            }
            return;
        }
        unsafe { write_synthesized_value(property.slot, property.kind, value) };
    }

    unsafe fn synthesized_slot(
        object: *mut c_void,
        selector: *const c_void,
        setter: bool,
    ) -> Option<ResolvedSynthesizedProperty> {
        if object.is_null() || selector.is_null() {
            return None;
        }
        let selector_name = unsafe { sel_getName(selector) };
        if selector_name.is_null() {
            return None;
        }
        let selector_name = unsafe { CStr::from_ptr(selector_name) }.to_string_lossy();
        let mut class = unsafe { object_getClass(object) };
        while !class.is_null() {
            let mut property_count = 0;
            let properties = unsafe { class_copyPropertyList(class, &mut property_count) };
            let property_slice = if properties.is_null() {
                &[][..]
            } else {
                unsafe { std::slice::from_raw_parts(properties, property_count as usize) }
            };
            let mut resolved = None;
            for &property in property_slice {
                let property_name = unsafe { property_getName(property) };
                if property_name.is_null() {
                    continue;
                }
                let property_name = unsafe { CStr::from_ptr(property_name) }.to_string_lossy();
                if property_name.is_empty() {
                    continue;
                }
                let accessor_name = if setter {
                    if property_has_attribute(property, b"R\0") {
                        continue;
                    }
                    copy_property_attribute(property, b"S\0")
                        .unwrap_or_else(|| super::property_setter_name(property_name.as_ref()))
                } else {
                    copy_property_attribute(property, b"G\0").unwrap_or_else(|| property_name.to_string())
                };
                if accessor_name != selector_name {
                    continue;
                }
                let Some(backing_name) = copy_property_attribute(property, b"V\0") else {
                    continue;
                };
                let Ok(backing_name) = CString::new(backing_name) else {
                    continue;
                };
                let ivar = unsafe { class_getInstanceVariable(class, backing_name.as_ptr()) };
                if ivar.is_null() {
                    continue;
                }
                let encoding = unsafe { ivar_getTypeEncoding(ivar) };
                if encoding.is_null() {
                    continue;
                }
                let encoding = unsafe { CStr::from_ptr(encoding) }.to_string_lossy();
                let Some(kind) =
                    super::synthesized_property_kind(encoding.trim_start_matches(['r', 'n', 'N', 'o', 'O', 'R', 'V']))
                else {
                    continue;
                };
                let offset = match usize::try_from(unsafe { ivar_getOffset(ivar) }) {
                    Ok(offset) => offset,
                    Err(_) => continue,
                };
                let Some(address) = (object as usize).checked_add(offset) else {
                    continue;
                };
                let manual_kvo_key = (setter && unsafe { property_uses_manual_kvo(class, property_name.as_ref()) })
                    .then(|| property_name.into_owned());
                resolved = Some(ResolvedSynthesizedProperty {
                    slot: address,
                    kind,
                    ownership: synthesized_property_ownership(property),
                    atomic: !property_has_attribute(property, b"N\0"),
                    manual_kvo_key,
                });
                break;
            }
            unsafe { libc::free(properties.cast()) };
            if resolved.is_some() {
                return resolved;
            }
            class = unsafe { class_getSuperclass(class) };
        }
        None
    }

    unsafe fn synthesized_property_ownership(property: *mut c_void) -> PropertyOwnership {
        let attributes = unsafe { property_getAttributes(property) };
        if attributes.is_null() {
            return PropertyOwnership::Assign;
        }
        let attributes = unsafe { CStr::from_ptr(attributes) }.to_string_lossy();
        if attributes.split(',').any(|attribute| attribute == "W") {
            PropertyOwnership::Weak
        } else if attributes.split(',').any(|attribute| attribute == "C") {
            PropertyOwnership::Copy
        } else if attributes.split(',').any(|attribute| attribute == "&") {
            PropertyOwnership::Retain
        } else {
            PropertyOwnership::Assign
        }
    }

    fn property_has_attribute(property: *mut c_void, attribute: &'static [u8]) -> bool {
        copy_property_attribute(property, attribute).is_some()
    }

    fn copy_property_attribute(property: *mut c_void, attribute: &'static [u8]) -> Option<String> {
        let attribute = CStr::from_bytes_with_nul(attribute).ok()?;
        let value = unsafe { property_copyAttributeValue(property, attribute.as_ptr()) };
        if value.is_null() {
            return None;
        }
        let value_string = unsafe { CStr::from_ptr(value) }.to_string_lossy().into_owned();
        unsafe { libc::free(value.cast()) };
        Some(value_string)
    }

    unsafe fn property_uses_manual_kvo(class: *mut c_void, property_name: &str) -> bool {
        let Ok(property_name) = CString::new(property_name) else {
            return false;
        };
        unsafe { rf_objc_property_uses_manual_kvo(class, property_name.as_ptr()) == 1 }
    }

    unsafe fn notify_manual_kvo(object: *mut c_void, property_name: &str, will_change: bool) -> bool {
        let Ok(property_name) = CString::new(property_name) else {
            return false;
        };
        let mut exception = RawExceptionInfo::default();
        let status = if will_change {
            unsafe { rf_objc_try_kvo_will_change(object, property_name.as_ptr(), &mut exception) }
        } else {
            unsafe { rf_objc_try_kvo_did_change(object, property_name.as_ptr(), &mut exception) }
        };
        status == 0
    }

    unsafe fn load_atomic_synthesized_object(
        object: *mut c_void,
        selector: *const c_void,
        slot: usize,
    ) -> Option<usize> {
        let offset = isize::try_from(slot.checked_sub(object as usize)?).ok()?;
        let mut result = std::ptr::null_mut();
        let mut exception = RawExceptionInfo::default();
        let status = unsafe {
            rf_objc_try_atomic_get_object(
                object,
                selector,
                offset,
                &mut result,
                &mut exception as *mut RawExceptionInfo,
            )
        };
        (status == 0).then_some(result as usize)
    }

    unsafe fn store_atomic_synthesized_object(
        object: *mut c_void,
        selector: *const c_void,
        slot: usize,
        value: *mut c_void,
        should_copy: bool,
    ) -> bool {
        let Some(offset) = slot
            .checked_sub(object as usize)
            .and_then(|offset| isize::try_from(offset).ok())
        else {
            return false;
        };
        let mut exception = RawExceptionInfo::default();
        unsafe {
            rf_objc_try_atomic_set_object(
                object,
                selector,
                offset,
                value,
                should_copy,
                &mut exception as *mut RawExceptionInfo,
            ) == 0
        }
    }

    unsafe fn load_atomic_synthesized_value(address: usize, kind: ScalarKind) -> Option<usize> {
        let width = kind.width()?;
        let mut value = 0usize;
        let mut exception = RawExceptionInfo::default();
        let status = unsafe {
            rf_objc_try_atomic_load_value(
                address as *const c_void,
                (&mut value as *mut usize).cast(),
                width,
                &mut exception as *mut RawExceptionInfo,
            )
        };
        (status == 0).then(|| unsafe { read_synthesized_value((&value as *const usize) as usize, kind) })
    }

    unsafe fn store_atomic_synthesized_value(address: usize, kind: ScalarKind, value: usize) -> bool {
        let Some(width) = kind.width() else {
            return false;
        };
        let mut exception = RawExceptionInfo::default();
        unsafe {
            rf_objc_try_atomic_store_value(
                address as *mut c_void,
                (&value as *const usize).cast(),
                width,
                &mut exception as *mut RawExceptionInfo,
            ) == 0
        }
    }

    unsafe fn retain_synthesized_object(object: *mut c_void) -> Option<usize> {
        if object.is_null() {
            return Some(0);
        }
        let mut retained: *mut c_void = std::ptr::null_mut();
        let mut exception = RawExceptionInfo::default();
        let status = unsafe {
            rf_objc_try_retain(
                object,
                &mut retained as *mut *mut c_void,
                &mut exception as *mut RawExceptionInfo,
            )
        };
        (status == 0 && !retained.is_null()).then_some(retained as usize)
    }

    unsafe fn copy_synthesized_object(object: *mut c_void) -> Option<usize> {
        if object.is_null() {
            return Some(0);
        }
        let mut copied: *mut c_void = std::ptr::null_mut();
        let mut exception = RawExceptionInfo::default();
        let status = unsafe {
            rf_objc_try_copy(
                object,
                &mut copied as *mut *mut c_void,
                &mut exception as *mut RawExceptionInfo,
            )
        };
        (status == 0 && !copied.is_null()).then_some(copied as usize)
    }

    unsafe fn release_synthesized_object(object: *mut c_void) {
        let mut exception = RawExceptionInfo::default();
        let _ = unsafe { rf_objc_try_release(object, &mut exception as *mut RawExceptionInfo) };
    }

    unsafe fn store_synthesized_weak(address: usize, object: *mut c_void) -> bool {
        let mut exception = RawExceptionInfo::default();
        let status = unsafe {
            rf_objc_try_store_weak(
                address as *mut *mut c_void,
                object,
                &mut exception as *mut RawExceptionInfo,
            )
        };
        status == 0
    }

    unsafe fn load_synthesized_weak(address: usize) -> Option<usize> {
        let mut loaded: *mut c_void = std::ptr::null_mut();
        let mut exception = RawExceptionInfo::default();
        let status = unsafe {
            rf_objc_try_load_weak(
                address as *mut *mut c_void,
                &mut loaded as *mut *mut c_void,
                &mut exception as *mut RawExceptionInfo,
            )
        };
        (status == 0).then_some(loaded as usize)
    }

    pub fn install_manual_kvo(class: usize, class_name: &str, property_name: &str) -> BridgeResult<()> {
        let property_name_c = CString::new(property_name).expect("checked property name");
        let status = unsafe { rf_objc_install_manual_kvo(class as *mut c_void, property_name_c.as_ptr()) };
        match status {
            0 => Ok(()),
            1 => Err(BridgeError::ClassMutationFailed {
                class_name: class_name.to_owned(),
                member_name: property_name.to_owned(),
                operation: "manual KVO marker or class-method synthesis",
            }),
            2 => Err(BridgeError::ClassMutationFailed {
                class_name: class_name.to_owned(),
                member_name: property_name.to_owned(),
                operation: "manual KVO capability validation",
            }),
            status => Err(BridgeError::ShimContractViolation {
                operation: "manual KVO synthesis",
                status,
            }),
        }
    }

    pub fn install_managed_property_lifecycle(class: usize, class_name: &str) -> BridgeResult<()> {
        let status = unsafe { rf_objc_install_managed_property_lifecycle(class as *mut c_void) };
        match status {
            0 => Ok(()),
            1 => Err(BridgeError::ClassMutationFailed {
                class_name: class_name.to_owned(),
                member_name: "__iosRustFrida_managedPropertyLifecycle".into(),
                operation: "managed property lifecycle marker synthesis",
            }),
            2 => Err(BridgeError::ClassMutationFailed {
                class_name: class_name.to_owned(),
                member_name: "dealloc".into(),
                operation: "managed property lifecycle synthesis",
            }),
            status => Err(BridgeError::ShimContractViolation {
                operation: "managed property lifecycle synthesis",
                status,
            }),
        }
    }

    unsafe fn read_synthesized_value(address: usize, kind: ScalarKind) -> usize {
        match kind {
            ScalarKind::Bool => usize::from(unsafe { (address as *const u8).read_unaligned() != 0 }),
            ScalarKind::I8 => unsafe { (address as *const i8).read_unaligned() as isize as usize },
            ScalarKind::U8 => unsafe { (address as *const u8).read_unaligned() as usize },
            ScalarKind::I16 => unsafe { (address as *const i16).read_unaligned() as isize as usize },
            ScalarKind::U16 => unsafe { (address as *const u16).read_unaligned() as usize },
            ScalarKind::I32 => unsafe { (address as *const i32).read_unaligned() as isize as usize },
            ScalarKind::U32 => unsafe { (address as *const u32).read_unaligned() as usize },
            ScalarKind::I64 => unsafe { (address as *const i64).read_unaligned() as usize },
            ScalarKind::U64 => unsafe { (address as *const u64).read_unaligned() as usize },
            ScalarKind::Isize => unsafe { (address as *const isize).read_unaligned() as usize },
            ScalarKind::Usize | ScalarKind::Pointer => unsafe { (address as *const usize).read_unaligned() },
            ScalarKind::Void => 0,
        }
    }

    unsafe fn write_synthesized_value(address: usize, kind: ScalarKind, value: usize) {
        match kind {
            ScalarKind::Bool => unsafe { (address as *mut u8).write_unaligned(u8::from(value != 0)) },
            ScalarKind::I8 => unsafe { (address as *mut i8).write_unaligned(value as i8) },
            ScalarKind::U8 => unsafe { (address as *mut u8).write_unaligned(value as u8) },
            ScalarKind::I16 => unsafe { (address as *mut i16).write_unaligned(value as i16) },
            ScalarKind::U16 => unsafe { (address as *mut u16).write_unaligned(value as u16) },
            ScalarKind::I32 => unsafe { (address as *mut i32).write_unaligned(value as i32) },
            ScalarKind::U32 => unsafe { (address as *mut u32).write_unaligned(value as u32) },
            ScalarKind::I64 => unsafe { (address as *mut i64).write_unaligned(value as i64) },
            ScalarKind::U64 => unsafe { (address as *mut u64).write_unaligned(value as u64) },
            ScalarKind::Isize => unsafe { (address as *mut isize).write_unaligned(value as isize) },
            ScalarKind::Usize | ScalarKind::Pointer => unsafe { (address as *mut usize).write_unaligned(value) },
            ScalarKind::Void => {}
        }
    }

    pub fn add_method(
        class: usize,
        class_name: &str,
        class_method: bool,
        selector: usize,
        implementation: usize,
        type_encoding: &str,
    ) -> BridgeResult<()> {
        let target = if class_method {
            unsafe { object_getClass(class as *const c_void) }
        } else {
            class as *mut c_void
        };
        let selector_name = unsafe { sel_getName(selector as *const c_void) };
        let member_name = if selector_name.is_null() {
            format!("selector {selector:#x}")
        } else {
            unsafe { CStr::from_ptr(selector_name) }.to_string_lossy().into_owned()
        };
        let type_encoding_c = CString::new(type_encoding).expect("checked type encoding");
        let added = unsafe {
            class_addMethod(
                target,
                selector as *const c_void,
                implementation as *const c_void,
                type_encoding_c.as_ptr(),
            )
        };
        if added {
            Ok(())
        } else {
            Err(BridgeError::ClassMutationFailed {
                class_name: class_name.to_owned(),
                member_name,
                operation: if class_method {
                    "class method addition"
                } else {
                    "instance method addition"
                },
            })
        }
    }

    pub fn register_class_pair(class: usize) -> BridgeResult<()> {
        unsafe { objc_registerClassPair(class as *mut c_void) };
        Ok(())
    }

    pub unsafe fn dispose_class_pair(class: usize) {
        unsafe { objc_disposeClassPair(class as *mut c_void) };
    }

    pub fn validate_object(raw: usize) -> BridgeResult<()> {
        checked_object_address(raw)?;
        validate_range(raw, mem::size_of::<usize>(), IvarAccess::Read).map_err(|error| {
            BridgeError::InvalidObjectPointer {
                address: raw,
                reason: error.to_string(),
            }
        })?;

        // VM checks do not establish object identity. The unsafe caller owns
        // that invariant before this runtime probe is reached.
        let class = unsafe { object_getClass(raw as *const c_void) } as usize;
        if class == 0 {
            return Err(BridgeError::InvalidObjectPointer {
                address: raw,
                reason: "object_getClass returned null".into(),
            });
        }
        validate_range(class, mem::size_of::<usize>(), IvarAccess::Read).map_err(|error| {
            BridgeError::InvalidObjectPointer {
                address: raw,
                reason: format!("runtime class pointer {class:#x} is invalid: {error}"),
            }
        })
    }

    pub unsafe fn retain(raw: usize) -> BridgeResult<usize> {
        let mut retained = std::ptr::null_mut();
        let mut exception = RawExceptionInfo::default();
        let status = unsafe {
            rf_objc_try_retain(
                raw as *mut c_void,
                &mut retained as *mut *mut c_void,
                &mut exception as *mut RawExceptionInfo,
            )
        };
        shim_status(status, "retain", exception)?;
        let retained = retained as usize;
        if retained == 0 {
            return Err(BridgeError::InvalidObjectPointer {
                address: raw,
                reason: "objc_retain returned null".into(),
            });
        }
        Ok(retained)
    }

    pub unsafe fn release(raw: usize) -> BridgeResult<()> {
        let mut exception = RawExceptionInfo::default();
        let status = unsafe { rf_objc_try_release(raw as *mut c_void, &mut exception as *mut RawExceptionInfo) };
        shim_status(status, "release", exception)
    }

    pub fn resolve_ivar(raw: usize, name: &str, width: usize, access: IvarAccess) -> BridgeResult<IvarSlot> {
        validate_object(raw)?;
        let class = unsafe { object_getClass(raw as *const c_void) };
        let name_c = CString::new(name).expect("checked ivar name");
        let ivar = unsafe { class_getInstanceVariable(class, name_c.as_ptr()) };
        if ivar.is_null() {
            return Err(BridgeError::IvarNotFound(name.to_owned()));
        }

        let offset = unsafe { ivar_getOffset(ivar) };
        let offset = usize::try_from(offset).map_err(|_| BridgeError::InvalidMemoryRange {
            address: raw,
            length: width,
            reason: format!("ivar {name} has a negative offset"),
        })?;
        let instance_size = unsafe { class_getInstanceSize(class) };
        let end = offset.checked_add(width).ok_or_else(|| BridgeError::IvarOutOfBounds {
            name: name.to_owned(),
            offset,
            width,
            instance_size,
        })?;
        if end > instance_size {
            return Err(BridgeError::IvarOutOfBounds {
                name: name.to_owned(),
                offset,
                width,
                instance_size,
            });
        }
        let address = raw.checked_add(offset).ok_or_else(|| BridgeError::InvalidMemoryRange {
            address: raw,
            length: width,
            reason: "ivar address overflow".into(),
        })?;
        validate_range(address, width, access)?;

        let encoding = unsafe { ivar_getTypeEncoding(ivar) };
        let type_encoding = if encoding.is_null() {
            None
        } else {
            Some(unsafe { CStr::from_ptr(encoding) }.to_string_lossy().into_owned())
        };
        Ok(IvarSlot {
            address,
            offset,
            width,
            type_encoding,
        })
    }

    pub unsafe fn read_scalar(address: usize, kind: ScalarKind) -> BridgeResult<ScalarValue> {
        let value = match kind {
            ScalarKind::Void => unreachable!("void width is rejected before reading"),
            ScalarKind::Bool => ScalarValue::Bool(unsafe { (address as *const i8).read_unaligned() } != 0),
            ScalarKind::I8 => ScalarValue::I8(unsafe { (address as *const i8).read_unaligned() }),
            ScalarKind::U8 => ScalarValue::U8(unsafe { (address as *const u8).read_unaligned() }),
            ScalarKind::I16 => ScalarValue::I16(unsafe { (address as *const i16).read_unaligned() }),
            ScalarKind::U16 => ScalarValue::U16(unsafe { (address as *const u16).read_unaligned() }),
            ScalarKind::I32 => ScalarValue::I32(unsafe { (address as *const i32).read_unaligned() }),
            ScalarKind::U32 => ScalarValue::U32(unsafe { (address as *const u32).read_unaligned() }),
            ScalarKind::I64 => ScalarValue::I64(unsafe { (address as *const i64).read_unaligned() }),
            ScalarKind::U64 => ScalarValue::U64(unsafe { (address as *const u64).read_unaligned() }),
            ScalarKind::Isize => ScalarValue::Isize(unsafe { (address as *const isize).read_unaligned() }),
            ScalarKind::Usize => ScalarValue::Usize(unsafe { (address as *const usize).read_unaligned() }),
            ScalarKind::Pointer => ScalarValue::Pointer(unsafe { (address as *const usize).read_unaligned() }),
        };
        Ok(value)
    }

    pub unsafe fn write_scalar(address: usize, value: ScalarValue) -> BridgeResult<()> {
        match value {
            ScalarValue::Void => unreachable!("void width is rejected before writing"),
            ScalarValue::Bool(value) => unsafe { (address as *mut i8).write_unaligned(i8::from(value)) },
            ScalarValue::I8(value) => unsafe { (address as *mut i8).write_unaligned(value) },
            ScalarValue::U8(value) => unsafe { (address as *mut u8).write_unaligned(value) },
            ScalarValue::I16(value) => unsafe { (address as *mut i16).write_unaligned(value) },
            ScalarValue::U16(value) => unsafe { (address as *mut u16).write_unaligned(value) },
            ScalarValue::I32(value) => unsafe { (address as *mut i32).write_unaligned(value) },
            ScalarValue::U32(value) => unsafe { (address as *mut u32).write_unaligned(value) },
            ScalarValue::I64(value) => unsafe { (address as *mut i64).write_unaligned(value) },
            ScalarValue::U64(value) => unsafe { (address as *mut u64).write_unaligned(value) },
            ScalarValue::Isize(value) => unsafe { (address as *mut isize).write_unaligned(value) },
            ScalarValue::Usize(value) => unsafe { (address as *mut usize).write_unaligned(value) },
            ScalarValue::Pointer(value) => unsafe { (address as *mut usize).write_unaligned(value) },
        }
        Ok(())
    }

    pub unsafe fn dispatch(
        receiver: usize,
        selector: usize,
        arguments: &[usize],
        return_kind: ScalarKind,
    ) -> BridgeResult<ScalarValue> {
        validate_object(receiver)?;
        let mut result = 0usize;
        let mut exception = RawExceptionInfo::default();
        let status = unsafe {
            rf_objc_try_msg_send(
                receiver as *mut c_void,
                selector as *const c_void,
                arguments.as_ptr(),
                arguments.len(),
                return_kind as u32,
                &mut result as *mut usize,
                &mut exception as *mut RawExceptionInfo,
            )
        };
        shim_status(status, "message dispatch", exception)?;
        Ok(ScalarValue::from_return_word(return_kind, result))
    }

    fn shim_status(status: i32, operation: &'static str, exception: RawExceptionInfo) -> BridgeResult<()> {
        match status {
            0 => Ok(()),
            1 => Err(BridgeError::ObjectiveCException(ObjcException {
                name: exception_string(&exception.name),
                reason: exception_string(&exception.reason),
            })),
            status => Err(BridgeError::ShimContractViolation { operation, status }),
        }
    }

    fn exception_string(buffer: &[c_char]) -> Option<String> {
        let length = buffer.iter().position(|byte| *byte == 0).unwrap_or(buffer.len());
        if length == 0 {
            return None;
        }
        let bytes = buffer[..length].iter().map(|byte| *byte as u8).collect::<Vec<_>>();
        Some(String::from_utf8_lossy(&bytes).into_owned())
    }

    fn validate_range(address: usize, length: usize, access: IvarAccess) -> BridgeResult<()> {
        if length == 0 {
            return Err(BridgeError::InvalidMemoryRange {
                address,
                length,
                reason: "range length must be non-zero".into(),
            });
        }
        let end = address
            .checked_add(length)
            .ok_or_else(|| BridgeError::InvalidMemoryRange {
                address,
                length,
                reason: "range overflow".into(),
            })?;
        let required = match access {
            IvarAccess::Read => VM_PROT_READ,
            IvarAccess::Write => VM_PROT_WRITE,
        };
        let mut cursor = address;
        while cursor < end {
            let region = region_at(cursor).map_err(|reason| BridgeError::InvalidMemoryRange {
                address,
                length,
                reason,
            })?;
            if region.protection & required == 0 {
                return Err(BridgeError::InvalidMemoryRange {
                    address,
                    length,
                    reason: format!(
                        "region {:#x}..{:#x} lacks {} permission",
                        region.start,
                        region.end,
                        match access {
                            IvarAccess::Read => "read",
                            IvarAccess::Write => "write",
                        }
                    ),
                });
            }
            cursor = region.end.min(end);
        }
        Ok(())
    }

    struct Region {
        start: usize,
        end: usize,
        protection: libc::vm_prot_t,
    }

    fn region_at(cursor: usize) -> Result<Region, String> {
        let mut nesting_depth = 0;
        loop {
            let mut address = cursor as libc::mach_vm_address_t;
            let mut size = 0 as libc::mach_vm_size_t;
            let mut info = VmRegionSubmapInfo64::default();
            let mut info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
            let result = unsafe {
                mach_vm_region_recurse(
                    mach_task_self_,
                    &mut address,
                    &mut size,
                    &mut nesting_depth,
                    &mut info as *mut VmRegionSubmapInfo64 as *mut libc::integer_t,
                    &mut info_count,
                )
            };
            if result != 0 || size == 0 {
                return Err(format!(
                    "mach_vm_region_recurse failed at {cursor:#x}: kern_return={result}"
                ));
            }
            if info.is_submap != 0 {
                nesting_depth = nesting_depth
                    .checked_add(1)
                    .ok_or_else(|| "Mach VM nesting depth overflow".to_owned())?;
                continue;
            }
            let start = usize::try_from(address).map_err(|_| "Mach region start does not fit usize")?;
            let size = usize::try_from(size).map_err(|_| "Mach region size does not fit usize")?;
            let end = start.checked_add(size).ok_or("Mach region range overflow")?;
            if start > cursor || end <= cursor {
                return Err(format!("unmapped gap at {cursor:#x}"));
            }
            return Ok(Region {
                start,
                end,
                protection: info.protection,
            });
        }
    }
}

#[cfg(not(any(target_os = "ios", target_os = "macos")))]
mod platform {
    use super::{BridgeError, BridgeResult, IvarAccess, IvarSlot, ScalarKind, ScalarValue};

    pub fn lookup_class(_name: &str) -> BridgeResult<Option<usize>> {
        Err(BridgeError::PlatformUnavailable)
    }

    pub fn register_selector(_name: &str) -> BridgeResult<usize> {
        Err(BridgeError::PlatformUnavailable)
    }

    pub fn allocate_class_pair(_superclass: usize, _name: &str) -> BridgeResult<usize> {
        Err(BridgeError::PlatformUnavailable)
    }

    pub fn add_ivar(
        _class: usize,
        _class_name: &str,
        _name: &str,
        _size: usize,
        _alignment_log2: u8,
        _type_encoding: &str,
    ) -> BridgeResult<()> {
        Err(BridgeError::PlatformUnavailable)
    }

    pub fn validate_synthesized_accessors(
        _class: usize,
        _class_name: &str,
        _getter_name: &str,
        _setter_name: Option<&str>,
    ) -> BridgeResult<()> {
        Err(BridgeError::PlatformUnavailable)
    }

    pub fn add_method(
        _class: usize,
        _class_name: &str,
        _class_method: bool,
        _selector: usize,
        _implementation: usize,
        _type_encoding: &str,
    ) -> BridgeResult<()> {
        Err(BridgeError::PlatformUnavailable)
    }

    pub fn add_synthesized_property(
        _class: usize,
        _class_name: &str,
        _name: &str,
        _type_encoding: &str,
        _backing_name: &str,
        _read_only: bool,
        _ownership: super::PropertyOwnership,
        _atomic: bool,
        _getter_name: &str,
        _setter_name: Option<&str>,
    ) -> BridgeResult<()> {
        Err(BridgeError::PlatformUnavailable)
    }

    pub fn install_managed_property_lifecycle(_class: usize, _class_name: &str) -> BridgeResult<()> {
        Err(BridgeError::PlatformUnavailable)
    }

    pub fn install_manual_kvo(_class: usize, _class_name: &str, _property_name: &str) -> BridgeResult<()> {
        Err(BridgeError::PlatformUnavailable)
    }

    pub fn register_class_pair(_class: usize) -> BridgeResult<()> {
        Err(BridgeError::PlatformUnavailable)
    }

    pub unsafe fn dispose_class_pair(_class: usize) {}

    pub fn validate_object(raw: usize) -> BridgeResult<()> {
        super::checked_object_address(raw)?;
        Err(BridgeError::PlatformUnavailable)
    }

    pub unsafe fn retain(_raw: usize) -> BridgeResult<usize> {
        Err(BridgeError::PlatformUnavailable)
    }

    pub unsafe fn release(_raw: usize) -> BridgeResult<()> {
        Err(BridgeError::PlatformUnavailable)
    }

    pub fn resolve_ivar(_raw: usize, _name: &str, _width: usize, _access: IvarAccess) -> BridgeResult<IvarSlot> {
        Err(BridgeError::PlatformUnavailable)
    }

    pub unsafe fn read_scalar(_address: usize, _kind: ScalarKind) -> BridgeResult<ScalarValue> {
        Err(BridgeError::PlatformUnavailable)
    }

    pub unsafe fn write_scalar(_address: usize, _value: ScalarValue) -> BridgeResult<()> {
        Err(BridgeError::PlatformUnavailable)
    }

    pub unsafe fn dispatch(
        _receiver: usize,
        _selector: usize,
        _arguments: &[usize],
        _return_kind: ScalarKind,
    ) -> BridgeResult<ScalarValue> {
        Err(BridgeError::PlatformUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_publish_the_exception_and_argument_boundaries() {
        let apple = cfg!(any(target_os = "ios", target_os = "macos"));
        let capabilities = ObjectBridge::new().capabilities();
        assert_eq!(capabilities.max_message_arguments, 6);
        assert_eq!(capabilities.available, apple);
        assert_eq!(capabilities.catches_objc_exceptions, apple);
        assert!(!capabilities.accepts_tagged_object_pointers);
        assert_eq!(capabilities.supports_scalar_and_pointer_dispatch, apple);
        assert_eq!(capabilities.supports_raw_ivar_access, apple);
        assert_eq!(capabilities.supports_property_accessors, apple);
        assert_eq!(capabilities.supports_dynamic_class_registration, apple);
        assert_eq!(capabilities.supports_dynamic_property_synthesis, apple);
        assert_eq!(
            ObjectBridge::new().exception_boundary(),
            if apple {
                ObjcExceptionBoundary::ContainedByAppleShim
            } else {
                ObjcExceptionBoundary::PlatformUnavailable
            }
        );
        assert_eq!(
            ObjectBridge::new().require_caught_exceptions(),
            if apple {
                Ok(())
            } else {
                Err(BridgeError::ExceptionContainmentUnavailable)
            }
        );
    }

    #[test]
    fn names_are_trimmed_and_reject_empty_or_nul_input() {
        assert_eq!(checked_name("  NSObject  ", "class"), Ok("NSObject"));
        assert!(matches!(
            checked_name("  ", "class"),
            Err(BridgeError::InvalidName { kind: "class", .. })
        ));
        assert!(matches!(
            checked_name("bad\0name", "selector"),
            Err(BridgeError::InvalidName {
                kind: "selector",
                reason: "name contains an interior NUL byte"
            })
        ));
    }

    #[test]
    fn scalar_kinds_have_stable_widths_and_argument_words() {
        assert_eq!(ScalarKind::Void.width(), None);
        assert_eq!(ScalarKind::Bool.width(), Some(1));
        assert_eq!(ScalarKind::U32.width(), Some(4));
        assert_eq!(ScalarKind::Pointer.width(), Some(std::mem::size_of::<usize>()));
        assert_eq!(ScalarValue::Bool(true).to_argument_word(), Ok(1));
        assert_eq!(ScalarValue::I8(-1).to_argument_word(), Ok(usize::MAX));
        assert_eq!(ScalarValue::Pointer(0).to_argument_word(), Ok(0));
        assert_eq!(ScalarKind::Void as u32, 0);
        assert_eq!(ScalarKind::Pointer as u32, 12);
        assert_eq!(
            ScalarValue::from_return_word(ScalarKind::I8, usize::MAX),
            ScalarValue::I8(-1)
        );
        assert_eq!(
            ScalarValue::from_return_word(ScalarKind::Pointer, 0x1234),
            ScalarValue::Pointer(0x1234)
        );
    }

    #[test]
    fn synthesized_property_layout_accepts_only_word_sized_runtime_safe_types() {
        assert_eq!(synthesized_property_layout("i").unwrap().size, 4);
        assert_eq!(
            synthesized_property_layout("@\"NSObject\"").unwrap().size,
            std::mem::size_of::<usize>()
        );
        assert_eq!(property_setter_name("URL"), "setURL:");
        assert!(matches!(
            checked_property_name("bad-name"),
            Err(BridgeError::InvalidName { kind: "property", .. })
        ));
        assert!(matches!(
            checked_property_name(&"a".repeat(MAX_SYNTHESIZED_PROPERTY_NAME_LENGTH + 1)),
            Err(BridgeError::InvalidName { kind: "property", .. })
        ));
        assert!(matches!(
            synthesized_property_layout("{Pair=ii}"),
            Err(BridgeError::UnsupportedPropertyType { .. })
        ));
    }

    #[test]
    fn synthesized_property_kinds_match_accessor_storage_widths() {
        assert_eq!(synthesized_property_kind("B"), Some(ScalarKind::Bool));
        assert_eq!(synthesized_property_kind("ri"), Some(ScalarKind::I32));
        assert_eq!(synthesized_property_kind("Q"), Some(ScalarKind::U64));
        assert_eq!(synthesized_property_kind("@\"NSObject\""), Some(ScalarKind::Pointer));
        assert_eq!(synthesized_property_kind("{Pair=ii}"), None);
    }

    #[test]
    fn synthesized_property_accessors_validate_custom_selector_shapes() {
        let custom = SynthesizedPropertyOptions::new(false, PropertyOwnership::Retain)
            .with_getter("currentTitle")
            .with_setter("replaceTitle:")
            .with_atomic(true);
        assert!(custom.atomic);
        assert_eq!(
            synthesized_property_accessor_names("title", &custom),
            Ok(("currentTitle".into(), Some("replaceTitle:".into())))
        );
        assert_eq!(
            synthesized_property_accessor_names("title", &SynthesizedPropertyOptions::default()),
            Ok(("title".into(), Some("setTitle:".into())))
        );
        assert!(!SynthesizedPropertyOptions::default().atomic);
        assert_eq!(SynthesizedPropertyOptions::default().kvo, PropertyKvo::Automatic);
        assert!(synthesized_property_accessor_names(
            "title",
            &SynthesizedPropertyOptions::new(false, PropertyOwnership::Assign).with_getter("badGetter:")
        )
        .is_err());
        assert!(synthesized_property_accessor_names(
            "title",
            &SynthesizedPropertyOptions::new(false, PropertyOwnership::Assign).with_getter("bad,Getter")
        )
        .is_err());
        assert!(synthesized_property_accessor_names(
            "title",
            &SynthesizedPropertyOptions::new(false, PropertyOwnership::Assign).with_setter("badSetter")
        )
        .is_err());
        assert!(synthesized_property_accessor_names(
            "title",
            &SynthesizedPropertyOptions::new(false, PropertyOwnership::Assign).with_setter("bad,Setter:")
        )
        .is_err());
        assert!(synthesized_property_accessor_names(
            "title",
            &SynthesizedPropertyOptions::new(true, PropertyOwnership::Assign).with_setter("setTitle:")
        )
        .is_err());
        assert!(synthesized_property_accessor_names(
            "title",
            &SynthesizedPropertyOptions::new(true, PropertyOwnership::Assign).with_kvo(PropertyKvo::Manual)
        )
        .is_err());
    }

    #[test]
    fn property_ownership_names_and_lifecycle_are_stable() {
        assert_eq!(PropertyOwnership::Assign.name(), "assign");
        assert_eq!(PropertyOwnership::Retain.name(), "retain");
        assert_eq!(PropertyOwnership::Copy.name(), "copy");
        assert_eq!(PropertyOwnership::Weak.name(), "weak");
        assert!(!PropertyOwnership::Assign.requires_managed_lifecycle());
        assert!(PropertyOwnership::Retain.requires_managed_lifecycle());
        assert!(PropertyOwnership::Copy.requires_managed_lifecycle());
        assert!(PropertyOwnership::Weak.requires_managed_lifecycle());
        assert_eq!(PropertyKvo::Automatic.name(), "automatic");
        assert_eq!(PropertyKvo::Manual.name(), "manual");
    }

    #[test]
    fn typed_ivar_encodings_are_checked_conservatively() {
        assert_eq!(validate_ivar_kind("_count", ScalarKind::I32, Some("ri")), Ok(()));
        assert_eq!(
            validate_ivar_kind("_delegate", ScalarKind::Pointer, Some("@\"NSObject\"")),
            Ok(())
        );
        assert_eq!(
            validate_ivar_kind("_count", ScalarKind::U64, Some("i")),
            Err(BridgeError::IvarTypeMismatch {
                name: "_count".into(),
                requested: ScalarKind::U64,
                encoding: "i".into(),
            })
        );
    }

    #[test]
    fn dispatch_argument_validation_is_bounded() {
        let too_many = [ScalarValue::Usize(0); MAX_MESSAGE_ARGUMENTS + 1];
        assert_eq!(
            checked_arguments(&too_many),
            Err(BridgeError::TooManyArguments {
                supplied: MAX_MESSAGE_ARGUMENTS + 1,
                maximum: MAX_MESSAGE_ARGUMENTS,
            })
        );
        assert_eq!(
            checked_arguments(&[ScalarValue::Usize(1), ScalarValue::Void]),
            Err(BridgeError::VoidArgument { index: 1 })
        );
    }

    #[test]
    fn object_pointer_preflight_rejects_null_and_tagged_or_unaligned_values() {
        assert_eq!(checked_object_address(0), Err(BridgeError::NullPointer));
        assert_eq!(
            checked_object_address(0x1001),
            Err(BridgeError::MisalignedObjectPointer {
                address: 0x1001,
                alignment: std::mem::align_of::<usize>(),
            })
        );
        assert_eq!(checked_object_address(0x1000), Ok(()));
    }

    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    #[test]
    fn non_apple_backend_is_deterministic() {
        let bridge = ObjectBridge::new();
        assert!(!bridge.is_available());
        assert_eq!(bridge.lookup_class("NSObject"), Err(BridgeError::PlatformUnavailable));
        assert_eq!(
            bridge.register_selector("description"),
            Err(BridgeError::PlatformUnavailable)
        );
        assert_eq!(
            unsafe { bridge.retain_object(0) }.expect_err("null is rejected before platform dispatch"),
            BridgeError::NullPointer
        );
        assert_eq!(
            unsafe { bridge.validate_object_pointer(0) },
            Err(BridgeError::NullPointer)
        );
        assert_eq!(
            unsafe { bridge.retain_object(0x1000) }.expect_err("valid-shaped pointer reaches platform boundary"),
            BridgeError::PlatformUnavailable
        );
        assert!(matches!(
            bridge.allocate_subclass("NSObject", "RustFridaHostProbe"),
            Err(BridgeError::PlatformUnavailable)
        ));
    }

    #[test]
    fn errors_expose_raw_ivar_and_exception_boundaries() {
        assert!(BridgeError::ExceptionContainmentUnavailable
            .to_string()
            .contains("unavailable on this target"));
        assert_eq!(
            BridgeError::ObjectiveCException(ObjcException {
                name: Some("NSInvalidArgumentException".into()),
                reason: Some("bad selector".into()),
            })
            .to_string(),
            "Objective-C exception NSInvalidArgumentException: bad selector"
        );
        assert!(BridgeError::MisalignedObjectPointer {
            address: 1,
            alignment: std::mem::align_of::<usize>(),
        }
        .to_string()
        .contains("tagged pointers"));
    }
}
