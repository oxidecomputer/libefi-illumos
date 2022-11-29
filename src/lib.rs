use anyhow::{anyhow, Result};
use libefi_sys::{
    efi_alloc_and_read,
    efi_free,
    dk_gpt_t,
    dk_part_t,
};
use std::ffi::CStr;
use std::fs::File;
use std::marker::PhantomData;
use std::ptr::{addr_of, addr_of_mut};
use std::os::unix::io::AsFd;
use std::os::unix::io::AsRawFd;
use uuid::Uuid;

const GPT_ENT_TYPE_EFI: Uuid =
    Uuid::from_fields(
        0xc12a7328,
        0xf81f,
        0x11d2,
        &[0xba,0x4b,0x00,0xa0,0xc9,0x3e,0xc9,0x3b]
    );

const GPT_ENT_TYPE_ILLUMOS_BOOT: Uuid =
    Uuid::from_fields(
        0x6a82cb45,
        0x1dd2,
        0x11b2,
        &[0x99,0xa6,0x08,0x00,0x20,0x73,0x66,0x31]
    );

const GPT_ENT_TYPE_ILLUMOS_UFS: Uuid =
    Uuid::from_fields(
        0x6a85cf4d,
        0x1dd2,
        0x11b2,
        &[0x99,0xa6,0x08,0x00,0x20,0x73,0x66,0x31]
    );

const GPT_ENT_TYPE_ILLUMOS_ZFS: Uuid =
    Uuid::from_fields(
        0x6a898cc3,
        0x1dd2,
        0x11b2,
        &[0x99,0xa6,0x08,0x00,0x20,0x73,0x66,0x31]
    );

const GPT_ENT_TYPE_RESERVED: Uuid =
    Uuid::from_fields(
        0x6a945a3b,
        0x1dd2,
        0x11b2,
        &[0x99,0xa6,0x08,0x00,0x20,0x73,0x66,0x31]
    );

#[derive(Clone, Debug)]
pub enum GptEntryType {
    Efi,
    IllumosBoot,
    IllumosUFS,
    IllumosZFS,
    Reserved,
    Unknown(Uuid),
}

impl From<Uuid> for GptEntryType {
    fn from(uuid: Uuid) -> Self {
        match uuid {
            GPT_ENT_TYPE_EFI => GptEntryType::Efi,
            GPT_ENT_TYPE_ILLUMOS_BOOT => GptEntryType::IllumosBoot,
            GPT_ENT_TYPE_ILLUMOS_UFS => GptEntryType::IllumosUFS,
            GPT_ENT_TYPE_ILLUMOS_ZFS => GptEntryType::IllumosZFS,
            GPT_ENT_TYPE_RESERVED => GptEntryType::Reserved,
            _ => GptEntryType::Unknown(uuid),
        }
    }
}

pub struct Gpt {
    gpt: *mut dk_gpt_t,
}

impl Gpt {
    pub fn new(disk: File) -> Result<Self> {
        let fd = disk.as_fd();

        let mut gpt = std::ptr::null_mut();
        let retval = unsafe {
            efi_alloc_and_read(
                fd.as_raw_fd(),
                &mut gpt,
            )
        };
        match retval {
            n if n >= 0 => {
                println!("Slice Number: {n}");
                Ok(Self {
                    gpt,
                })
            }
            libefi_sys::VT_EIO => Err(anyhow!("I/O Error")),
            libefi_sys::VT_ERROR => Err(anyhow!("Unknown error occured")),
            libefi_sys::VT_EINVAL => Err(anyhow!("EFI label not found")),
            n => Err(anyhow!("Unhandled error: {n}")),
        }
    }

    fn inner(&self) -> &dk_gpt_t {
        unsafe { &*self.gpt }
    }

    fn inner_mut(&mut self) -> &mut dk_gpt_t {
        unsafe { &mut *self.gpt }
    }

    fn raw_partitions(&self) -> &[dk_part_t] {
        let gpt = self.inner();
        let count = gpt.efi_nparts as usize;
        let partitions_ptr = addr_of!(gpt.efi_parts).cast();
        unsafe {
            std::slice::from_raw_parts(partitions_ptr, count)
        }
    }

    fn raw_partitions_mut(&mut self) -> &mut [dk_part_t] {
        let gpt = self.inner_mut();
        let count = gpt.efi_nparts as usize;
        let partitions_ptr = addr_of_mut!(gpt.efi_parts).cast();
        unsafe {
            std::slice::from_raw_parts_mut(partitions_ptr, count)
        }
    }

    pub fn block_size(&self) -> u32 {
        self.inner().efi_lbasize
    }

    pub fn guid(&self) -> Uuid {
        let guid_ptr: *const u8 = addr_of!(self.inner().efi_disk_uguid) as *const u8;
        let uuid = unsafe {
            std::slice::from_raw_parts(guid_ptr, 16)
        };
        Uuid::from_slice_le(uuid).unwrap()
    }

    pub fn partitions(&self) -> impl Iterator<Item = Partition<'_>> {
        self.raw_partitions()
            .iter()
            .enumerate()
            .map(|(index, part)| {
                Partition {
                    index,
                    part,
                    phantom: PhantomData,
                }
            })
    }

    pub fn partitions_mut(&mut self) -> impl Iterator<Item = PartitionMut<'_>> {
        self.raw_partitions_mut()
            .iter_mut()
            .map(|part| {
                PartitionMut {
                    part,
                    phantom: PhantomData,
                }
            })
    }
}

impl Drop for Gpt {
    fn drop(&mut self) {
        unsafe {
            efi_free(self.gpt)
        }
    }
}

pub struct Partition<'a> {
    index: usize,
    part: *const dk_part_t,
    phantom: PhantomData<&'a dk_part_t>,
}

impl<'a> Partition<'a> {
    fn inner(&self) -> &dk_part_t {
        unsafe { &*self.part }
    }

    pub fn index(&self) -> usize {
        self.index
    }

    pub fn start(&self) -> u64 {
        self.inner().p_start
    }

    pub fn size(&self) -> u64 {
        self.inner().p_size
    }

    pub fn partition_type_guid(&self) -> GptEntryType {
        let guid_ptr: *const u8 = addr_of!(self.inner().p_guid) as *const u8;
        let uuid = unsafe {
            std::slice::from_raw_parts(guid_ptr, 16)
        };
        Uuid::from_slice_le(uuid).unwrap().into()
    }

    pub fn tag(&self) -> u16 {
        self.inner().p_tag
    }

    pub fn flag(&self) -> u16 {
        self.inner().p_flag
    }

    pub fn name(&self) -> &CStr {
        if !self.inner().p_name.as_slice().contains(&0) {
            return <&CStr>::default();
        }
        let name_ptr = addr_of!(self.inner().p_name) as *const i8;
        unsafe {
            CStr::from_ptr(name_ptr)
        }
    }

    pub fn user_guid(&self) -> Uuid {
        let guid_ptr: *const u8 = addr_of!(self.inner().p_uguid) as *const u8;
        let uuid = unsafe {
            std::slice::from_raw_parts(guid_ptr, 16)
        };
        Uuid::from_slice_le(uuid).unwrap()
    }
}

pub struct PartitionMut<'a> {
    part: *mut dk_part_t,
    phantom: PhantomData<&'a mut dk_part_t>,
}
