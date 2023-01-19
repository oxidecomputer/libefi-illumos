use libefi_sys::{
    dk_gpt_t, dk_part_t, efi_alloc_and_init, efi_alloc_and_read, efi_free, efi_reserved_sectors,
    efi_use_whole_disk, efi_write, V_BOOT, V_ROOT, V_SWAP, V_UNASSIGNED, V_USR,
};
use std::ffi::CStr;
use std::fs::File;
use std::fs::OpenOptions;
use std::os::fd::RawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsFd;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::ptr::{addr_of, addr_of_mut};
use uuid::Uuid;

const GPT_ENT_TYPE_EFI: Uuid = Uuid::from_fields(
    0xc12a7328,
    0xf81f,
    0x11d2,
    &[0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b],
);

const GPT_ENT_TYPE_ILLUMOS_BOOT: Uuid = Uuid::from_fields(
    0x6a82cb45,
    0x1dd2,
    0x11b2,
    &[0x99, 0xa6, 0x08, 0x00, 0x20, 0x73, 0x66, 0x31],
);

const GPT_ENT_TYPE_ILLUMOS_UFS: Uuid = Uuid::from_fields(
    0x6a85cf4d,
    0x1dd2,
    0x11b2,
    &[0x99, 0xa6, 0x08, 0x00, 0x20, 0x73, 0x66, 0x31],
);

const GPT_ENT_TYPE_ILLUMOS_ZFS: Uuid = Uuid::from_fields(
    0x6a898cc3,
    0x1dd2,
    0x11b2,
    &[0x99, 0xa6, 0x08, 0x00, 0x20, 0x73, 0x66, 0x31],
);

const GPT_ENT_TYPE_RESERVED: Uuid = Uuid::from_fields(
    0x6a945a3b,
    0x1dd2,
    0x11b2,
    &[0x99, 0xa6, 0x08, 0x00, 0x20, 0x73, 0x66, 0x31],
);

#[derive(Clone, Debug)]
pub enum GptEntryType {
    Efi,
    IllumosBoot,
    IllumosUFS,
    IllumosZFS,
    Reserved,
    Other(Uuid),
}

impl From<Uuid> for GptEntryType {
    fn from(uuid: Uuid) -> Self {
        match uuid {
            GPT_ENT_TYPE_EFI => GptEntryType::Efi,
            GPT_ENT_TYPE_ILLUMOS_BOOT => GptEntryType::IllumosBoot,
            GPT_ENT_TYPE_ILLUMOS_UFS => GptEntryType::IllumosUFS,
            GPT_ENT_TYPE_ILLUMOS_ZFS => GptEntryType::IllumosZFS,
            GPT_ENT_TYPE_RESERVED => GptEntryType::Reserved,
            _ => GptEntryType::Other(uuid),
        }
    }
}

#[derive(Clone, Debug)]
pub enum PartitionTag {
    Unassigned,
    Boot,
    Root,
    Swap,
    User,
}

impl From<PartitionTag> for u16 {
    fn from(tag: PartitionTag) -> u16 {
        use PartitionTag::*;
        match tag {
            Unassigned => V_UNASSIGNED,
            Boot => V_BOOT,
            Root => V_ROOT,
            Swap => V_SWAP,
            User => V_USR,
        }
        .try_into()
        .expect("Partition tags should all be u16")
    }
}

/// Errors which may be returned when interfacing with libefi.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    IO(#[from] std::io::Error),
    #[error("I/O Error accessing device")]
    DeviceIO,
    #[error("Unknown error occurred")]
    Unknown,
    #[error("EFI label not found")]
    LabelNotFound,
    #[error("EFI label contains incorrect data")]
    LabelInvalid,
    #[error("Not enough space exists on the device")]
    NoSpace,
    #[error("Unhandled error (code: {0})")]
    Unhandled(i32),
}

pub struct Gpt {
    file: File,
    gpt: *mut dk_gpt_t,
}

impl Gpt {
    // Internal helper to provide consistency to open options.
    fn open<P: AsRef<Path>>(path: P) -> Result<File, Error> {
        Ok(OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NDELAY)
            .open(path)?)
    }

    /// Reads the partition table from the path, if one exists.
    pub fn read<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let file = Self::open(path)?;
        let fd = file.as_fd().as_raw_fd();

        let mut gpt = std::ptr::null_mut();
        let retval = unsafe { efi_alloc_and_read(fd, &mut gpt) };
        match retval {
            n if n >= 0 => {
                // 'n' can be greater than zero if we pass a path to a
                // particular slice within the GPT.
                //
                // However, for this API, we don't care about that info, and
                // drop it.
                Ok(Self { file, gpt })
            }
            libefi_sys::VT_EIO => Err(Error::DeviceIO),
            libefi_sys::VT_ERROR => Err(Error::Unknown),
            libefi_sys::VT_EINVAL => Err(Error::LabelNotFound),
            n => Err(Error::Unhandled(n)),
        }
    }

    /// Initializes the partition table at the path.
    ///
    /// The partition is not actually written back to the device until
    /// [Self::write] is called.
    pub fn initialize<P: AsRef<Path>>(path: P, partition_count: u32) -> Result<Self, Error> {
        let file = Self::open(path)?;
        let fd = file.as_fd().as_raw_fd();

        let mut gpt = std::ptr::null_mut();
        let retval = unsafe { efi_alloc_and_init(fd, partition_count, &mut gpt) };
        match retval {
            0 => Ok(Self { file, gpt }),
            libefi_sys::VT_EIO => Err(Error::DeviceIO),
            retval => Err(Error::Unhandled(retval)),
        }
    }

    fn fd(&self) -> RawFd {
        self.file.as_fd().as_raw_fd()
    }

    fn raw_partitions(&self) -> &[dk_part_t] {
        unsafe {
            let count = (*self.gpt).efi_nparts as usize;
            let partitions_ptr = addr_of!((*self.gpt).efi_parts).cast();
            std::slice::from_raw_parts(partitions_ptr, count)
        }
    }

    fn raw_partitions_mut(&mut self) -> &mut [dk_part_t] {
        unsafe {
            let count = (*self.gpt).efi_nparts as usize;

            // NOTE: It's important to ensure that we don't have multiple mut
            // references to the underlying gpt object.
            let partitions_ptr = addr_of_mut!((*self.gpt).efi_parts).cast();

            std::slice::from_raw_parts_mut(partitions_ptr, count)
        }
    }

    pub fn block_size(&self) -> u32 {
        unsafe { (*self.gpt).efi_lbasize }
    }

    pub fn guid(&self) -> Uuid {
        let uuid = unsafe {
            let guid_ptr = addr_of!((*self.gpt).efi_disk_uguid) as *const u8;
            std::slice::from_raw_parts(guid_ptr, 16)
        };
        Uuid::from_slice_le(uuid).unwrap()
    }

    pub fn partitions(&self) -> impl Iterator<Item = Partition<'_>> {
        self.raw_partitions()
            .iter()
            .enumerate()
            .map(|(index, part)| Partition { index, part })
    }

    pub fn partitions_mut(&mut self) -> impl Iterator<Item = PartitionMut<'_>> {
        self.raw_partitions_mut()
            .iter_mut()
            .enumerate()
            .map(|(index, part)| PartitionMut { index, part })
    }

    /// Calculates the number of blocks to create the reserved partition.
    ///
    /// See [Self::block_size] for the block size.
    pub fn reserved_sectors(&self) -> u32 {
        unsafe { efi_reserved_sectors(self.gpt) }
    }

    // Takes any space that is not contained in the disk label and adds it
    // to the last physically non-zero area before the reserved slice.
    //    pub fn use_whole_disk(&mut self) -> Result<(), Error> {
    //        let retval = unsafe { efi_use_whole_disk(self.fd()) };
    //
    //        match retval {
    //            0 => Ok(()),
    //            libefi_sys::VT_EIO => Err(Error::DeviceIO),
    //            libefi_sys::VT_ERROR => Err(Error::Unknown),
    //            libefi_sys::VT_EINVAL => Err(Error::LabelInvalid),
    //            libefi_sys::VT_ENOSPC => Err(Error::NoSpace),
    //            retval => Err(Error::Unhandled(retval)),
    //        }
    //    }

    /// Writes the partition table and creates a protective MBR (Master Boot
    /// Record).
    pub fn write(&mut self) -> Result<(), Error> {
        let retval = unsafe { efi_write(self.fd(), self.gpt) };

        match retval {
            0 => Ok(()),
            libefi_sys::VT_EIO => Err(Error::DeviceIO),
            libefi_sys::VT_ERROR => Err(Error::Unknown),
            libefi_sys::VT_EINVAL => Err(Error::LabelInvalid),
            libefi_sys::VT_ENOSPC => Err(Error::NoSpace),
            retval => Err(Error::Unhandled(retval)),
        }
    }
}

impl Drop for Gpt {
    fn drop(&mut self) {
        unsafe { efi_free(self.gpt) }
    }
}

pub struct Partition<'a> {
    index: usize,
    part: &'a dk_part_t,
}

impl<'a> Partition<'a> {
    pub fn index(&self) -> usize {
        self.index
    }

    pub fn start(&self) -> u64 {
        self.part.p_start
    }

    pub fn size(&self) -> u64 {
        self.part.p_size
    }

    pub fn partition_type_guid(&self) -> GptEntryType {
        let guid_ptr: *const u8 = addr_of!(self.part.p_guid) as *const u8;
        let uuid = unsafe { std::slice::from_raw_parts(guid_ptr, 16) };
        Uuid::from_slice_le(uuid).unwrap().into()
    }

    pub fn tag(&self) -> u16 {
        self.part.p_tag
    }

    pub fn flag(&self) -> u16 {
        self.part.p_flag
    }

    pub fn name(&self) -> &CStr {
        if !self.part.p_name.as_slice().contains(&0) {
            return <&CStr>::default();
        }
        let name_ptr = addr_of!(self.part.p_name) as *const i8;
        unsafe { CStr::from_ptr(name_ptr) }
    }

    pub fn user_guid(&self) -> Uuid {
        let guid_ptr: *const u8 = addr_of!(self.part.p_uguid) as *const u8;
        let uuid = unsafe { std::slice::from_raw_parts(guid_ptr, 16) };
        Uuid::from_slice_le(uuid).unwrap()
    }
}

pub struct PartitionMut<'a> {
    index: usize,
    part: &'a mut dk_part_t,
}

impl<'a> PartitionMut<'a> {
    pub fn index(&self) -> usize {
        self.index
    }

    pub fn start(&self) -> u64 {
        self.part.p_start
    }

    pub fn set_start(&mut self, start: u64) {
        self.part.p_start = start;
    }

    pub fn size(&self) -> u64 {
        self.part.p_size
    }

    pub fn set_size(&mut self, size: u64) {
        self.part.p_size = size;
    }

    pub fn partition_type_guid(&self) -> GptEntryType {
        let guid_ptr: *const u8 = addr_of!(self.part.p_guid) as *const u8;
        let uuid = unsafe { std::slice::from_raw_parts(guid_ptr, 16) };
        Uuid::from_slice_le(uuid).unwrap().into()
    }

    pub fn tag(&self) -> u16 {
        self.part.p_tag
    }

    pub fn set_tag(&mut self, tag: PartitionTag) {
        self.part.p_tag = tag.into();
    }

    pub fn flag(&self) -> u16 {
        self.part.p_flag
    }

    pub fn set_flag(&mut self, flag: u16) {
        self.part.p_flag = flag;
    }

    pub fn name(&self) -> &CStr {
        if !self.part.p_name.as_slice().contains(&0) {
            return <&CStr>::default();
        }
        let name_ptr = addr_of!(self.part.p_name) as *const i8;
        unsafe { CStr::from_ptr(name_ptr) }
    }

    pub fn set_name(&mut self, name: &std::ffi::CStr) {
        let src = name.to_bytes_with_nul();
        let src = unsafe { &*(src as *const [u8] as *const [i8]) };
        self.part.p_name.copy_from_slice(src);
    }

    pub fn user_guid(&self) -> Uuid {
        let guid_ptr: *const u8 = addr_of!(self.part.p_uguid) as *const u8;
        let uuid = unsafe { std::slice::from_raw_parts(guid_ptr, 16) };
        Uuid::from_slice_le(uuid).unwrap()
    }

    pub fn set_user_guid(&mut self, uuid: Uuid) {
        let bytes = uuid.to_bytes_le();
        let src = bytes.as_ptr();
        let dst = addr_of_mut!(self.part.p_uguid) as *mut u8;
        unsafe { std::ptr::copy(src, dst, 16) };
    }
}
