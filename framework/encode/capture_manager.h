/*
** Copyright (c) 2018-2022 Valve Corporation
** Copyright (c) 2018-2022 LunarG, Inc.
** Copyright (c) 2019-2023 Advanced Micro Devices, Inc. All rights reserved.
**
** Permission is hereby granted, free of charge, to any person obtaining a
** copy of this software and associated documentation files (the "Software"),
** to deal in the Software without restriction, including without limitation
** the rights to use, copy, modify, merge, publish, distribute, sublicense,
** and/or sell copies of the Software, and to permit persons to whom the
** Software is furnished to do so, subject to the following conditions:
**
** The above copyright notice and this permission notice shall be included in
** all copies or substantial portions of the Software.
**
** THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
** IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
** FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
** AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
** LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
** FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
** DEALINGS IN THE SOFTWARE.
*/

#ifndef GFXRECON_ENCODE_CAPTURE_MANAGER_H
#define GFXRECON_ENCODE_CAPTURE_MANAGER_H

#include "encode/capture_settings.h"
#include "encode/handle_unwrap_memory.h"
#include "encode/parameter_buffer.h"
#include "encode/parameter_encoder.h"
#include "format/api_call_id.h"
#include "format/format.h"
#include "format/platform_types.h"
#include "util/compressor.h"
#include "util/defines.h"
#include "util/file_output_stream.h"
#include "util/keyboard.h"

#include <atomic>
#include <cassert>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>
#include "util/file_path.h"

GFXRECON_BEGIN_NAMESPACE(gfxrecon)
GFXRECON_BEGIN_NAMESPACE(encode)

class CaptureManager
{
  public:
    typedef std::shared_mutex ApiCallMutexT;

    static format::HandleId GetUniqueId() { return ++unique_id_counter_; }

    static auto AcquireSharedApiCallLock() { return std::move(std::shared_lock<ApiCallMutexT>(api_call_mutex_)); }

    static auto AcquireExclusiveApiCallLock() { return std::move(std::unique_lock<ApiCallMutexT>(api_call_mutex_)); }

    HandleUnwrapMemory* GetHandleUnwrapMemory()
    {
        auto thread_data = GetThreadData();
        assert(thread_data != nullptr);
        thread_data->handle_unwrap_memory_.Reset();
        return &thread_data->handle_unwrap_memory_;
    }

    ParameterEncoder* BeginTrackedApiCallCapture(format::ApiCallId call_id)
    {
        if (capture_mode_ != kModeDisabled)
        {
            return InitApiCallCapture(call_id);
        }

        return nullptr;
    }

    ParameterEncoder* BeginApiCallCapture(format::ApiCallId call_id)
    {
        if ((capture_mode_ & kModeWrite) == kModeWrite)
        {
            return InitApiCallCapture(call_id);
        }

        return nullptr;
    }

    ParameterEncoder* BeginTrackedMethodCallCapture(format::ApiCallId call_id, format::HandleId object_id)
    {
        if (capture_mode_ != kModeDisabled)
        {
            return InitMethodCallCapture(call_id, object_id);
        }

        return nullptr;
    }

    ParameterEncoder* BeginMethodCallCapture(format::ApiCallId call_id, format::HandleId object_id)
    {
        if ((capture_mode_ & kModeWrite) == kModeWrite)
        {
            return InitMethodCallCapture(call_id, object_id);
        }

        return nullptr;
    }

    void EndApiCallCapture();

    void EndMethodCallCapture();

    void WriteFrameMarker(format::MarkerType marker_type);

    void EndFrame();

    bool ShouldTriggerScreenshot();

    util::ScreenshotFormat GetScreenshotFormat() { return screenshot_format_; }

    void CheckContinueCaptureForWriteMode();

    void CheckStartCaptureForTrackMode();

    bool IsTrimHotkeyPressed();

    CaptureSettings::RuntimeTriggerState GetRuntimeTriggerState();

    bool RuntimeTriggerEnabled();

    bool RuntimeTriggerDisabled();

    void WriteDisplayMessageCmd(const char* message);

    void WriteExeFileInfo(const gfxrecon::util::filepath::FileInfo& info);

    /// @brief Inject an Annotation block into the capture file.
    /// @param type Identifies the contents of data as plain, xml, or json text
    /// @param label The key or name of the annotation.
    /// @param data The value or payload text of the annotation.
    void WriteAnnotation(const format::AnnotationType type, const char* label, const char* data);

    virtual CaptureSettings::TraceSettings GetDefaultTraceSettings();

    bool GetIUnknownWrappingSetting() const { return iunknown_wrapping_; }
    auto GetForceCommandSerialization() const { return force_command_serialization_; }
    auto GetQueueZeroOnly() const { return queue_zero_only_; }
    auto GetAllowPipelineCompileRequired() const { return allow_pipeline_compile_required_; }

    bool     IsAnnotated() const { return rv_annotation_info_.rv_annotation; }
    uint16_t GetGPUVAMask() const { return rv_annotation_info_.gpuva_mask; }
    uint16_t GetDescriptorMask() const { return rv_annotation_info_.descriptor_mask; }
    uint64_t GetShaderIDMask() const { return rv_annotation_info_.shaderid_mask; }

    uint64_t GetBlockIndex()
    {
        auto thread_data = GetThreadData();
        return thread_data->block_index_ == 0 ? 0 : thread_data->block_index_ - 1;
    }

  protected:
    enum CaptureModeFlags : uint32_t
    {
        kModeDisabled      = 0x0,
        kModeWrite         = 0x01,
        kModeTrack         = 0x02,
        kModeWriteAndTrack = (kModeWrite | kModeTrack)
    };

    enum PageGuardMemoryMode : uint32_t
    {
        kMemoryModeDisabled,
        kMemoryModeShadowInternal,   // Internally managed shadow memory allocations.
        kMemoryModeShadowPersistent, // Externally managed shadow memory allocations.
        kMemoryModeExternal          // Imported host memory without shadow allocations.
    };

    typedef uint32_t CaptureMode;

    class ThreadData
    {
      public:
        ThreadData();

        ~ThreadData() {}

        std::vector<uint8_t>& GetScratchBuffer() { return scratch_buffer_; }

      public:
        const format::ThreadId                   thread_id_;
        format::ApiCallId                        call_id_;
        format::HandleId                         object_id_;
        std::unique_ptr<encode::ParameterBuffer> parameter_buffer_;
        std::unique_ptr<ParameterEncoder>        parameter_encoder_;
        std::vector<uint8_t>                     compressed_buffer_;
        HandleUnwrapMemory                       handle_unwrap_memory_;
        uint64_t                                 block_index_;

      private:
        static format::ThreadId GetThreadId();

      private:
        static std::mutex                                     count_lock_;
        static format::ThreadId                               thread_count_;
        static std::unordered_map<uint64_t, format::ThreadId> id_map_;

      private:
        // Used for combining multiple buffers for a single file write.
        std::vector<uint8_t> scratch_buffer_;
    };

  protected:
    static bool CreateInstance(std::function<CaptureManager*()> GetInstanceFunc,
                               std::function<void()>            NewInstanceFunc,
                               std::function<void()>            DeleteInstanceFunc);

    static void DestroyInstance(std::function<const CaptureManager*()> GetInstanceFunc);

    CaptureManager(format::ApiFamilyId api_family);

    virtual ~CaptureManager();

    bool Initialize(std::string base_filename, const CaptureSettings::TraceSettings& trace_settings);

    virtual void CreateStateTracker()                                                               = 0;
    virtual void DestroyStateTracker()                                                              = 0;
    virtual void WriteTrackedState(util::FileOutputStream* file_stream, format::ThreadId thread_id) = 0;

    ThreadData* GetThreadData()
    {
        if (!thread_data_)
        {
            thread_data_ = std::make_unique<ThreadData>();
        }
        return thread_data_.get();
    }

    bool                                GetForceFileFlush() const { return force_file_flush_; }
    CaptureSettings::MemoryTrackingMode GetMemoryTrackingMode() const { return memory_tracking_mode_; }
    bool                                GetPageGuardAlignBufferSizes() const { return page_guard_align_buffer_sizes_; }
    bool                                GetPageGuardTrackAhbMemory() const { return page_guard_track_ahb_memory_; }
    PageGuardMemoryMode                 GetPageGuardMemoryMode() const { return page_guard_memory_mode_; }
    const std::string&                  GetTrimKey() const { return trim_key_; }
    bool                                IsTrimEnabled() const { return trim_enabled_; }
    uint32_t                            GetCurrentFrame() const { return current_frame_; }
    CaptureMode                         GetCaptureMode() const { return capture_mode_; }
    bool                                GetDebugLayerSetting() const { return debug_layer_; }
    bool                                GetDebugDeviceLostSetting() const { return debug_device_lost_; }
    bool                                GetDisableDxrSetting() const { return disable_dxr_; }
    auto                                GetAccelStructPaddingSetting() const { return accel_struct_padding_; }

    std::string CreateTrimFilename(const std::string& base_filename, const CaptureSettings::TrimRange& trim_range);
    bool        CreateCaptureFile(const std::string& base_filename);
    void        ActivateTrimming();
    void        DeactivateTrimming();

    void WriteFileHeader();
    void BuildOptionList(const format::EnabledOptions&        enabled_options,
                         std::vector<format::FileOptionPair>* option_list);

    ParameterEncoder* InitApiCallCapture(format::ApiCallId call_id);

    ParameterEncoder* InitMethodCallCapture(format::ApiCallId call_id, format::HandleId object_id);

    void WriteResizeWindowCmd(format::HandleId surface_id, uint32_t width, uint32_t height);

    void WriteFillMemoryCmd(format::HandleId memory_id, uint64_t offset, uint64_t size, const void* data);

    void WriteCreateHeapAllocationCmd(uint64_t allocation_id, uint64_t allocation_size);

  protected:
    std::unique_ptr<util::Compressor> compressor_;
    std::mutex                        mapped_memory_lock_;
    util::Keyboard                    keyboard_;
    std::string                       screenshot_prefix_;
    util::ScreenshotFormat            screenshot_format_;
    static std::atomic<uint64_t>      block_index_;

    void WriteToFile(const void* data, size_t size);

    template <size_t N>
    void CombineAndWriteToFile(const std::pair<const void*, size_t> (&buffers)[N])
    {
        static_assert(N != 1, "Use WriteToFile(void*, size) when writing a single buffer.");

        // Combine buffers for a single write.
        std::vector<uint8_t>& scratch_buffer = GetThreadData()->GetScratchBuffer();
        scratch_buffer.clear();
        for (size_t i = 0; i < N; ++i)
        {
            const uint8_t* const data = reinterpret_cast<const uint8_t*>(buffers[i].first);
            const size_t         size = buffers[i].second;
            scratch_buffer.insert(scratch_buffer.end(), data, data + size);
        }

        WriteToFile(scratch_buffer.data(), scratch_buffer.size());
    }

  private:
    static void AtExit()
    {
        if (delete_instance_func_)
        {
            delete_instance_func_();
            delete_instance_func_ = nullptr;
        }
    }

  private:
    static uint32_t                                 instance_count_;
    static std::mutex                               instance_lock_;
    static thread_local std::unique_ptr<ThreadData> thread_data_;
    static std::atomic<format::HandleId>            unique_id_counter_;
    static ApiCallMutexT                            api_call_mutex_;

    const format::ApiFamilyId api_family_;

    std::unique_ptr<util::FileOutputStream> file_stream_;
    format::EnabledOptions                  file_options_;
    std::string                             base_filename_;
    bool                                    timestamp_filename_;
    bool                                    force_file_flush_;
    CaptureSettings::MemoryTrackingMode     memory_tracking_mode_;
    bool                                    page_guard_align_buffer_sizes_;
    bool                                    page_guard_track_ahb_memory_;
    bool                                    page_guard_unblock_sigsegv_;
    bool                                    page_guard_signal_handler_watcher_;
    PageGuardMemoryMode                     page_guard_memory_mode_;
    bool                                    trim_enabled_;
    std::vector<CaptureSettings::TrimRange> trim_ranges_;
    std::string                             trim_key_;
    uint32_t                                trim_key_frames_;
    uint32_t                                trim_key_first_frame_;
    size_t                                  trim_current_range_;
    uint32_t                                current_frame_;
    CaptureMode                             capture_mode_;
    bool                                    previous_hotkey_state_;
    CaptureSettings::RuntimeTriggerState    previous_runtime_trigger_state_;
    bool                                    debug_layer_;
    bool                                    debug_device_lost_;
    bool                                    screenshots_enabled_;
    std::vector<uint32_t>                   screenshot_indices_;
    bool                                    disable_dxr_;
    uint32_t                                accel_struct_padding_;
    bool                                    iunknown_wrapping_;
    bool                                    force_command_serialization_;
    bool                                    queue_zero_only_;
    bool                                    allow_pipeline_compile_required_;
    bool                                    quit_after_frame_ranges_;
    static std::function<void()>            delete_instance_func_;

    struct
    {
        bool     rv_annotation{ false };
        uint16_t gpuva_mask{ RvAnnotationUtil::kGPUVAMask };
        uint16_t descriptor_mask{ RvAnnotationUtil::kDescriptorMask };
        uint64_t shaderid_mask{ RvAnnotationUtil::kShaderIDMask };
    } rv_annotation_info_;
};

/*
Regarding mutex_for_create_destroy_handle_ and related lock/unlock functions. These are used to address the following
race condition during capture:

Sometimes an app will destroy some Vulkan handles in one thread (A) and create same type of Vulkan handle in another
thread (B). There is a gap of time in between when the real handle is destroyed, and when its wrappers were deleted from
map in thread A. If during this time period, thread B was able to run, and creates same type of handles, and if any of
the newly-created handles had the same value of those destroyed by thread A, we crash.

For example, lets say an app's thread A calls vkFreeCommandBuffers, and in thread B it calls vkAllocateCommandBuffers.

GFXR's default API lock is AcquireSharedApiCallLock(), but if every API handling only request shared lock, that means
there is actually no lock for them. Therefore execution could switch from one thread to another thread. If thread A
calls vkFreeCommandBuffers to free command buffer group GC-X, those real Vulkan handles get destroyed by the driver, and
GFXR will proceed to delete wrapper objects of GC-X from the corresponding map. During this time, thread B was able to
run, and calls vkAllocateCommandBuffers to create a group of command buffers GC-Y. But because GC-X was already
destroyed, the driver may return some of the same former handle values of GC-X, but their wrapper still exists, and
GFXR's insertion of the new wrapper into its map will fail. And thread B will delete the wrapper later, so for any
following process, there would be no wrapper for the real handle which will eventually provoke a crash.

Note: destruction of other things could also potentially have this problem. For example, replace the above
vkFreeCommandBuffers with vkDestroyCommandPool. This call will free all command buffers of the command pool.

Regarding mutex_for_create_destroy_handle_ :

For any create wrapper operation, the operation which delete real Vulkan handle and its wrapper in map must be atomic.
This means a real handle and its wrapper must both exist, or both not exist, for any create wrapper operation. In the
following code, shared locks were already added to create wrapper functions.

The functions LockForDestroyHandle and UnlockForDestroyHandle should be used during capture. This will add exclusive
lock to the deletion of handles and their wrapper.
*/

class ScopedDestroyLock
{
  public:
    ScopedDestroyLock(bool shared = false)
    {
        lock_shared_ = shared;
        if (shared)
        {
            mutex_for_create_destroy_handle_.lock_shared();
        }
        else
        {
            mutex_for_create_destroy_handle_.lock();
        }
    };

    ~ScopedDestroyLock()
    {
        if (lock_shared_)
        {
            mutex_for_create_destroy_handle_.unlock_shared();
        }
        else
        {
            mutex_for_create_destroy_handle_.unlock();
        }
    };

    ScopedDestroyLock(const ScopedDestroyLock&) = delete;

    ScopedDestroyLock(ScopedDestroyLock&&) = delete;

    ScopedDestroyLock& operator=(const ScopedDestroyLock&) = delete;

    ScopedDestroyLock& operator=(ScopedDestroyLock&&) = delete;

  private:
    bool                     lock_shared_ = false;
    static std::shared_mutex mutex_for_create_destroy_handle_;
};

GFXRECON_END_NAMESPACE(encode)
GFXRECON_END_NAMESPACE(gfxrecon)

#endif // GFXRECON_ENCODE_CAPTURE_MANAGER_H
