use wdk_alloc::WdkAllocator;

#[global_allocator]
pub static ALLOCATOR: WdkAllocator = WdkAllocator;
