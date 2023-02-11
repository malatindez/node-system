#pragma once
#include "events/event.hpp"
#include "include/library-pch.hpp"

namespace node_system::events
{
    class FilesChangedEvent final : public Event
    {
    public:
        explicit FilesChangedEvent(std::vector<std::filesystem::path>&& files)
            : Event(EventType::FilesChanged, EventCategoryUtils), files_{ std::move(files) } {}

        FilesChangedEvent(FilesChangedEvent&&) = default;
        FilesChangedEvent(FilesChangedEvent const&) = default;
        FilesChangedEvent& operator=(FilesChangedEvent&&) = delete;
        FilesChangedEvent& operator=(FilesChangedEvent const&) = delete;

        [[nodiscard]] inline std::vector<std::filesystem::path> const& files_changed() { return files_; }
        EVENT_CLASS_TYPE(FilesChanged)
    private:
        std::vector<std::filesystem::path> files_;
    };
}
namespace utils
{
    class FileWatcher
    {
    public:

        explicit FileWatcher(::node_system::EventCallbackFn const& event_callback)
            : event_callback_{ event_callback } {}
        void AddPathToWatch(std::filesystem::path const& path, bool recursive = true);
        void OnUpdate();

    private:
        std::map<std::filesystem::path, std::filesystem::file_time_type> file_map_;
        ::node_system::EventCallbackFn event_callback_;
    };
}