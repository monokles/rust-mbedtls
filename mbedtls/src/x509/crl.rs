/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use core::fmt;
use core::ptr::NonNull;

use mbedtls_sys::*;

use crate::alloc::{Box as MbedtlsBox, List as MbedtlsList};
use crate::error::{Error, IntoResult, Result};
use crate::private::UnsafeFrom;

define!(
    #[c_ty(x509_crl)]
    #[repr(transparent)]
    /// Certificate Revocation List
    struct Crl;
    const drop: fn(&mut Self) = x509_crl_free;
    impl<'a> Into<ptr> {}
    impl<'a> UnsafeFrom<ptr> {}
);

impl Crl {
    pub fn from_der(der: &[u8]) -> Result<MbedtlsBox<Crl>> {
        let mut crl = MbedtlsBox::<Crl>::init()?;
        unsafe {
            x509_crl_parse_der((&mut (*crl)).into(), der.as_ptr(), der.len()).into_result()?;
        }
        Ok(crl)
    }

    //TODO convert
    pub fn from_pem(&mut self, pem: &[u8]) -> Result<MbedtlsBox<Crl>> {
        let mut crl = MbedtlsBox::<Crl>::init()?;
        unsafe {
            x509_crl_parse((&mut (*crl)).into(), pem.as_ptr(), pem.len()).into_result()?;
        }
        Ok(crl)
    }
}

impl fmt::Debug for Crl {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match crate::private::alloc_string_repeat(|buf, size| unsafe {
            x509_crl_info(buf, size, b"\0".as_ptr() as *const _, &self.inner)
        }) {
            Err(_) => Err(fmt::Error),
            Ok(s) => f.write_str(&s),
        }
    }
}

// TODO
// x509_crl_parse_file
//

//Box and List implementations taken from certificate.rs
impl MbedtlsBox<Crl> {
    fn init() -> Result<Self> {
        unsafe {
            let inner = crate::x509::certificate::forward_mbedtls_calloc(1, core::mem::size_of::<x509_crl>()) as *mut x509_crl;

            // If alignment is wrong it means someone pushed their own allocator to mbedtls
            // and that is not functioning correctly.
            assert_eq!(inner.align_offset(core::mem::align_of::<x509_crl>()), 0);

            let inner = NonNull::new(inner).ok_or(Error::X509AllocFailed)?;
            x509_crl_init(inner.as_ptr());

            Ok(MbedtlsBox { inner: inner.cast() })
        }
    }

    fn list_next(&self) -> Option<&MbedtlsBox<Crl>> {
        unsafe {
            <&Option<MbedtlsBox<Crl>> as UnsafeFrom<_>>::from(&(**self).inner.next)
                .unwrap()
                .as_ref()
        }
    }

    fn list_next_mut(&mut self) -> &mut Option<MbedtlsBox<Crl>> {
        unsafe { <&mut Option<MbedtlsBox<Crl>> as UnsafeFrom<_>>::from(&mut (**self).inner.next).unwrap() }
    }
}

impl<'a> UnsafeFrom<*const *mut x509_crl> for &'a Option<MbedtlsBox<Crl>> {
    unsafe fn from(ptr: *const *mut x509_crl) -> Option<&'a Option<MbedtlsBox<Crl>>> {
        (ptr as *const Option<MbedtlsBox<Crl>>).as_ref()
    }
}

impl<'a> UnsafeFrom<*mut *mut x509_crl> for &'a mut Option<MbedtlsBox<Crl>> {
    unsafe fn from(ptr: *mut *mut x509_crl) -> Option<&'a mut Option<MbedtlsBox<Crl>>> {
        (ptr as *mut Option<MbedtlsBox<Crl>>).as_mut()
    }
}

impl MbedtlsList<Crl> {
    pub fn new() -> Self {
        Self { inner: None }
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_none()
    }

    pub fn push(&mut self, crl: MbedtlsBox<Crl>) -> () {
        self.append(MbedtlsList::<Crl> { inner: Some(crl) });
    }

    pub fn pop_back(&mut self) -> Option<MbedtlsBox<Crl>> {
        let mut iter = self.iter_mut();

        let mut prev = iter.next()?;
        for cur in &mut iter {
            if cur.list_next().is_none() {
                return prev.list_next_mut().take();
            }
            prev = cur;
        }

        // no iterations in for loop: head equals tail
        self.inner.take()
    }

    pub fn pop_front(&mut self) -> Option<MbedtlsBox<Crl>> {
        let mut ret = self.inner.take()?;
        self.inner = ret.list_next_mut().take();
        Some(ret)
    }

    pub fn append(&mut self, list: MbedtlsList<Crl>) {
        let tail = match self.iter_mut().last() {
            None => &mut self.inner,
            Some(last) => last.list_next_mut(),
        };
        *tail = list.inner;
    }

    pub fn iter(&self) -> Iter<'_> {
        Iter { next: self.inner.as_ref() }
    }

    pub fn iter_mut(&mut self) -> IterMut<'_> {
        IterMut { next: self.inner.as_mut() }
    }

    pub(crate) unsafe fn inner_ffi_mut(&self) -> *mut x509_crl {
        self.inner
            .as_ref()
            .map_or(::core::ptr::null_mut(), |c| c.inner.as_ptr() as *mut x509_crl)
    }
}

impl<'a> UnsafeFrom<*const *const x509_crl> for &'a MbedtlsList<Crl> {
    unsafe fn from(ptr: *const *const x509_crl) -> Option<&'a MbedtlsList<Crl>> {
        if ptr.is_null() || (*ptr).is_null() {
            return None;
        }

        (ptr as *const MbedtlsList<Crl>).as_ref()
    }
}

impl<'a> UnsafeFrom<*mut *mut x509_crl> for &'a mut MbedtlsList<Crl> {
    unsafe fn from(ptr: *mut *mut x509_crl) -> Option<&'a mut MbedtlsList<Crl>> {
        if ptr.is_null() || (*ptr).is_null() {
            return None;
        }

        (ptr as *mut MbedtlsList<Crl>).as_mut()
    }
}

pub struct Iter<'a> {
    next: Option<&'a MbedtlsBox<Crl>>,
}

impl<'a> Iterator for Iter<'a> {
    type Item = &'a MbedtlsBox<Crl>;

    fn next(&mut self) -> Option<&'a MbedtlsBox<Crl>> {
        let ret = self.next.take()?;
        self.next = ret.list_next();
        Some(ret)
    }
}

pub struct IterMut<'a> {
    next: Option<&'a mut MbedtlsBox<Crl>>,
}

impl<'a> Iterator for IterMut<'a> {
    type Item = &'a mut MbedtlsBox<Crl>;

    fn next(&mut self) -> Option<&'a mut MbedtlsBox<Crl>> {
        let ret = self.next.take()?;
        unsafe {
            self.next = <&mut Option<MbedtlsBox<Crl>> as UnsafeFrom<_>>::from(&mut (**ret).inner.next).and_then(|v| v.as_mut());
        }
        Some(ret)
    }
}

impl Into<*const x509_crl> for &MbedtlsList<Crl> {
    fn into(self) -> *const x509_crl {
        self.inner
            .as_ref()
            .map_or(::core::ptr::null_mut(), |c| c.inner.as_ptr() as *const x509_crl)
    }
}

impl Into<*mut x509_crl> for &mut MbedtlsList<Crl> {
    fn into(self) -> *mut x509_crl {
        self.inner
            .as_ref()
            .map_or(::core::ptr::null_mut(), |c| c.inner.as_ptr() as *mut x509_crl)
    }
}
