#include <cstdio>
#include <exception>

#include "util/logging.h"
#include "format/file_processor.h"
#include "format/vulkan_replay_consumer.h"
#include "format/vulkan_decoder.h"

int main(int argc, char** argv)
{
    brimstone::util::logging::Init();

    brimstone::format::FileProcessor file_processor;

    std::string bin_file_name = "D:\\temp\\brimstone_test.bin";
    if (argc > 1)
    {
        bin_file_name = argv[1];
    }

    if (file_processor.Initialize(bin_file_name))
    {
        brimstone::format::VulkanDecoder        decoder;
        brimstone::format::VulkanReplayConsumer replay_consumer;

        replay_consumer.SetFatalErrorHandler([](const char* message) { throw std::runtime_error(message); });

        decoder.AddConsumer(&replay_consumer);
        file_processor.AddDecoder(&decoder);

        try
        {
            file_processor.ProcessAllFrames();
        }
        catch (std::runtime_error error)
        {
            printf("Replay failed with error message: %s\n", error.what());
        }
        catch (...)
        {
            printf("Replay failed due to an unhandled exception\n");
        }
    }

    brimstone::util::logging::Release();

    return 0;
}
