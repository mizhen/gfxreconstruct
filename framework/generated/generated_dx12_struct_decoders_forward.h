/*
** Copyright (c) 2021 LunarG, Inc.
**
** Permission is hereby granted, free of charge, to any person obtaining a copy
** of this software and associated documentation files (the "Software"), to
** deal in the Software without restriction, including without limitation the
** rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
** sell copies of the Software, and to permit persons to whom the Software is
** furnished to do so, subject to the following conditions:
**
** The above copyright notice and this permission notice shall be included in
** all copies or substantial portions of the Software.
**
** THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
** IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
** FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
** AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
** LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
** FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
** IN THE SOFTWARE.
*/

/*
** This file is generated from dx12_struct_decoders_forward_generator.py.
**
*/

#ifndef  GFXRECON_GENERATED_DX12_STRUCT_DECODERS_FORWARD_H
#define  GFXRECON_GENERATED_DX12_STRUCT_DECODERS_FORWARD_H


#include "generated_dx12_struct_decoders.h"


GFXRECON_BEGIN_NAMESPACE(gfxrecon)
GFXRECON_BEGIN_NAMESPACE(decode)

/*
** This part is generated from dxgi.h in Windows SDK: 10.0.19041.0
**
*/
size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_DXGI_FRAME_STATISTICS* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_DXGI_MAPPED_RECT* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_LUID* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_DXGI_ADAPTER_DESC* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_DXGI_OUTPUT_DESC* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_DXGI_SHARED_RESOURCE* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_DXGI_SURFACE_DESC* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_DXGI_SWAP_CHAIN_DESC* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_DXGI_ADAPTER_DESC1* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_DXGI_DISPLAY_COLOR_SPACE* wrapper);

/*
** This part is generated from dxgi1_2.h in Windows SDK: 10.0.19041.0
**
*/
size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_DXGI_OUTDUPL_MOVE_RECT* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_DXGI_OUTDUPL_DESC* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_DXGI_OUTDUPL_POINTER_POSITION* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_DXGI_OUTDUPL_POINTER_SHAPE_INFO* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_DXGI_OUTDUPL_FRAME_INFO* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_DXGI_MODE_DESC1* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_DXGI_SWAP_CHAIN_DESC1* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_DXGI_SWAP_CHAIN_FULLSCREEN_DESC* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_DXGI_PRESENT_PARAMETERS* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_DXGI_ADAPTER_DESC2* wrapper);

/*
** This part is generated from dxgi1_3.h in Windows SDK: 10.0.19041.0
**
*/
size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_DXGI_MATRIX_3X2_F* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_DXGI_DECODE_SWAP_CHAIN_DESC* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_DXGI_FRAME_STATISTICS_MEDIA* wrapper);

/*
** This part is generated from dxgi1_4.h in Windows SDK: 10.0.19041.0
**
*/
size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_DXGI_QUERY_VIDEO_MEMORY_INFO* wrapper);

/*
** This part is generated from dxgi1_5.h in Windows SDK: 10.0.19041.0
**
*/
size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_DXGI_HDR_METADATA_HDR10* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_DXGI_HDR_METADATA_HDR10PLUS* wrapper);

/*
** This part is generated from dxgi1_6.h in Windows SDK: 10.0.19041.0
**
*/
size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_DXGI_ADAPTER_DESC3* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_DXGI_OUTPUT_DESC1* wrapper);

/*
** This part is generated from dxgicommon.h in Windows SDK: 10.0.19041.0
**
*/
size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_DXGI_RATIONAL* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_DXGI_SAMPLE_DESC* wrapper);

/*
** This part is generated from dxgitype.h in Windows SDK: 10.0.19041.0
**
*/
size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_DXGI_RGB* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3DCOLORVALUE* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_DXGI_GAMMA_CONTROL* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_DXGI_GAMMA_CONTROL_CAPABILITIES* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_DXGI_MODE_DESC* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_DXGI_JPEG_DC_HUFFMAN_TABLE* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_DXGI_JPEG_AC_HUFFMAN_TABLE* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_DXGI_JPEG_QUANTIZATION_TABLE* wrapper);

/*
** This part is generated from d3d12.h in Windows SDK: 10.0.19041.0
**
*/
size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_COMMAND_QUEUE_DESC* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_INPUT_ELEMENT_DESC* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_SO_DECLARATION_ENTRY* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_VIEWPORT* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_BOX* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_DEPTH_STENCILOP_DESC* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_DEPTH_STENCIL_DESC* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_DEPTH_STENCIL_DESC1* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_RENDER_TARGET_BLEND_DESC* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_BLEND_DESC* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_RASTERIZER_DESC* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_SHADER_BYTECODE* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_STREAM_OUTPUT_DESC* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_INPUT_LAYOUT_DESC* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_CACHED_PIPELINE_STATE* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_GRAPHICS_PIPELINE_STATE_DESC* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_COMPUTE_PIPELINE_STATE_DESC* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_RT_FORMAT_ARRAY* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_PIPELINE_STATE_STREAM_DESC* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_FEATURE_DATA_D3D12_OPTIONS* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_FEATURE_DATA_D3D12_OPTIONS1* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_FEATURE_DATA_D3D12_OPTIONS2* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_FEATURE_DATA_ROOT_SIGNATURE* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_FEATURE_DATA_ARCHITECTURE* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_FEATURE_DATA_ARCHITECTURE1* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_FEATURE_DATA_FEATURE_LEVELS* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_FEATURE_DATA_SHADER_MODEL* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_FEATURE_DATA_FORMAT_SUPPORT* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_FEATURE_DATA_MULTISAMPLE_QUALITY_LEVELS* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_FEATURE_DATA_FORMAT_INFO* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_FEATURE_DATA_GPU_VIRTUAL_ADDRESS_SUPPORT* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_FEATURE_DATA_SHADER_CACHE* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_FEATURE_DATA_COMMAND_QUEUE_PRIORITY* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_FEATURE_DATA_D3D12_OPTIONS3* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_FEATURE_DATA_EXISTING_HEAPS* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_FEATURE_DATA_D3D12_OPTIONS4* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_FEATURE_DATA_SERIALIZATION* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_FEATURE_DATA_CROSS_NODE* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_FEATURE_DATA_D3D12_OPTIONS5* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_FEATURE_DATA_D3D12_OPTIONS6* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_FEATURE_DATA_D3D12_OPTIONS7* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_FEATURE_DATA_QUERY_META_COMMAND* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_RESOURCE_ALLOCATION_INFO* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_RESOURCE_ALLOCATION_INFO1* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_HEAP_PROPERTIES* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_HEAP_DESC* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_MIP_REGION* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_RESOURCE_DESC* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_RESOURCE_DESC1* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_DEPTH_STENCIL_VALUE* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_RANGE* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_RANGE_UINT64* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_SUBRESOURCE_RANGE_UINT64* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_SUBRESOURCE_INFO* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_TILED_RESOURCE_COORDINATE* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_TILE_REGION_SIZE* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_SUBRESOURCE_TILING* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_TILE_SHAPE* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_PACKED_MIP_INFO* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_RESOURCE_TRANSITION_BARRIER* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_RESOURCE_ALIASING_BARRIER* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_RESOURCE_UAV_BARRIER* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_SUBRESOURCE_FOOTPRINT* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_PLACED_SUBRESOURCE_FOOTPRINT* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_SAMPLE_POSITION* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_VIEW_INSTANCE_LOCATION* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_VIEW_INSTANCING_DESC* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_BUFFER_SRV* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_TEX1D_SRV* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_TEX1D_ARRAY_SRV* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_TEX2D_SRV* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_TEX2D_ARRAY_SRV* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_TEX3D_SRV* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_TEXCUBE_SRV* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_TEXCUBE_ARRAY_SRV* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_TEX2DMS_SRV* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_TEX2DMS_ARRAY_SRV* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_RAYTRACING_ACCELERATION_STRUCTURE_SRV* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_CONSTANT_BUFFER_VIEW_DESC* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_SAMPLER_DESC* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_BUFFER_UAV* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_TEX1D_UAV* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_TEX1D_ARRAY_UAV* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_TEX2D_UAV* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_TEX2D_ARRAY_UAV* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_TEX3D_UAV* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_BUFFER_RTV* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_TEX1D_RTV* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_TEX1D_ARRAY_RTV* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_TEX2D_RTV* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_TEX2DMS_RTV* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_TEX2D_ARRAY_RTV* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_TEX2DMS_ARRAY_RTV* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_TEX3D_RTV* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_TEX1D_DSV* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_TEX1D_ARRAY_DSV* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_TEX2D_DSV* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_TEX2D_ARRAY_DSV* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_TEX2DMS_DSV* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_TEX2DMS_ARRAY_DSV* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_DESCRIPTOR_HEAP_DESC* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_DESCRIPTOR_RANGE* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_ROOT_DESCRIPTOR_TABLE* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_ROOT_CONSTANTS* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_ROOT_DESCRIPTOR* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_STATIC_SAMPLER_DESC* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_ROOT_SIGNATURE_DESC* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_DESCRIPTOR_RANGE1* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_ROOT_DESCRIPTOR_TABLE1* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_ROOT_DESCRIPTOR1* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_ROOT_SIGNATURE_DESC1* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_CPU_DESCRIPTOR_HANDLE* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_GPU_DESCRIPTOR_HANDLE* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_DISCARD_REGION* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_QUERY_HEAP_DESC* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_QUERY_DATA_PIPELINE_STATISTICS* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_QUERY_DATA_SO_STATISTICS* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_STREAM_OUTPUT_BUFFER_VIEW* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_DRAW_ARGUMENTS* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_DRAW_INDEXED_ARGUMENTS* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_DISPATCH_ARGUMENTS* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_VERTEX_BUFFER_VIEW* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_INDEX_BUFFER_VIEW* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_COMMAND_SIGNATURE_DESC* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_WRITEBUFFERIMMEDIATE_PARAMETER* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_FEATURE_DATA_PROTECTED_RESOURCE_SESSION_SUPPORT* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_PROTECTED_RESOURCE_SESSION_DESC* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_META_COMMAND_PARAMETER_DESC* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_META_COMMAND_DESC* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_STATE_SUBOBJECT* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_STATE_OBJECT_CONFIG* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_GLOBAL_ROOT_SIGNATURE* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_LOCAL_ROOT_SIGNATURE* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_NODE_MASK* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_EXPORT_DESC* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_DXIL_LIBRARY_DESC* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_EXISTING_COLLECTION_DESC* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_SUBOBJECT_TO_EXPORTS_ASSOCIATION* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_DXIL_SUBOBJECT_TO_EXPORTS_ASSOCIATION* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_HIT_GROUP_DESC* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_RAYTRACING_SHADER_CONFIG* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_RAYTRACING_PIPELINE_CONFIG* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_RAYTRACING_PIPELINE_CONFIG1* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_STATE_OBJECT_DESC* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_GPU_VIRTUAL_ADDRESS_AND_STRIDE* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_GPU_VIRTUAL_ADDRESS_RANGE* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_GPU_VIRTUAL_ADDRESS_RANGE_AND_STRIDE* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_RAYTRACING_GEOMETRY_TRIANGLES_DESC* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_RAYTRACING_AABB* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_RAYTRACING_GEOMETRY_AABBS_DESC* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_RAYTRACING_ACCELERATION_STRUCTURE_POSTBUILD_INFO_DESC* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_RAYTRACING_ACCELERATION_STRUCTURE_POSTBUILD_INFO_COMPACTED_SIZE_DESC* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_RAYTRACING_ACCELERATION_STRUCTURE_POSTBUILD_INFO_TOOLS_VISUALIZATION_DESC* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_BUILD_RAYTRACING_ACCELERATION_STRUCTURE_TOOLS_VISUALIZATION_HEADER* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_RAYTRACING_ACCELERATION_STRUCTURE_POSTBUILD_INFO_SERIALIZATION_DESC* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_SERIALIZED_DATA_DRIVER_MATCHING_IDENTIFIER* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_SERIALIZED_RAYTRACING_ACCELERATION_STRUCTURE_HEADER* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_RAYTRACING_ACCELERATION_STRUCTURE_POSTBUILD_INFO_CURRENT_SIZE_DESC* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_RAYTRACING_INSTANCE_DESC* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_BUILD_RAYTRACING_ACCELERATION_STRUCTURE_DESC* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_RAYTRACING_ACCELERATION_STRUCTURE_PREBUILD_INFO* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_AUTO_BREADCRUMB_NODE* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_DRED_BREADCRUMB_CONTEXT* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_AUTO_BREADCRUMB_NODE1* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_DEVICE_REMOVED_EXTENDED_DATA* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_DRED_ALLOCATION_NODE* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_DRED_ALLOCATION_NODE1* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_DRED_AUTO_BREADCRUMBS_OUTPUT* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_DRED_AUTO_BREADCRUMBS_OUTPUT1* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_DRED_PAGE_FAULT_OUTPUT* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_DRED_PAGE_FAULT_OUTPUT1* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_DEVICE_REMOVED_EXTENDED_DATA1* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_DEVICE_REMOVED_EXTENDED_DATA2* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_FEATURE_DATA_PROTECTED_RESOURCE_SESSION_TYPE_COUNT* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_FEATURE_DATA_PROTECTED_RESOURCE_SESSION_TYPES* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_PROTECTED_RESOURCE_SESSION_DESC1* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_RENDER_PASS_BEGINNING_ACCESS_CLEAR_PARAMETERS* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_RENDER_PASS_ENDING_ACCESS_RESOLVE_SUBRESOURCE_PARAMETERS* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_RENDER_PASS_ENDING_ACCESS_RESOLVE_PARAMETERS* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_RENDER_PASS_RENDER_TARGET_DESC* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_RENDER_PASS_DEPTH_STENCIL_DESC* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_DISPATCH_RAYS_DESC* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_SUBRESOURCE_DATA* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_MEMCPY_DEST* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D12_DISPATCH_MESH_ARGUMENTS* wrapper);

/*
** This part is generated from d3dcommon.h in Windows SDK: 10.0.19041.0
**
*/
size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_D3D_SHADER_MACRO* wrapper);

/*
** This part is generated from guiddef.h in Windows SDK: 10.0.19041.0
**
*/
size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_GUID* wrapper);

/*
** This part is generated from windef.h in Windows SDK: 10.0.19041.0
**
*/
size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_tagRECT* wrapper);

size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded_tagPOINT* wrapper);

/*
** This part is generated from minwinbase.h in Windows SDK: 10.0.19041.0
**
*/
size_t DecodeStruct(const uint8_t* buffer, size_t buffer_size, Decoded__SECURITY_ATTRIBUTES* wrapper);



GFXRECON_END_NAMESPACE(decode)
GFXRECON_END_NAMESPACE(gfxrecon)

#endif
