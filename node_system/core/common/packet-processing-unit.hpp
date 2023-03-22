#pragma once
#include "session.hpp"
namespace node_system
{
    class PacketProcessingUnit
    {
    public:
        PacketProcessingUnit() = default;
        ~PacketProcessingUnit() = default;
        PacketProcessingUnit(const PacketProcessingUnit&) = delete;
        PacketProcessingUnit(PacketProcessingUnit&&) = delete;
        PacketProcessingUnit& operator=(const PacketProcessingUnit&) = delete;
        PacketProcessingUnit& operator=(PacketProcessingUnit&&) = delete;
        void AddSession(std::shared_ptr<Session> session)
        {
            sessions_.push_back(session);
        }
        void RemoveSession(std::shared_ptr<Session> session)
        {
            sessions_.erase(std::remove(sessions_.begin(), sessions_.end(), session), sessions_.end());
        }
        void Process()
        {
            for (auto& session : sessions_)
            {
                session->Process();
            }
            if(!sessions_.empty())
                sessions_.erase(
                    std::remove_if(
                        sessions_.begin(), sessions_.end(), 
                        [](const auto& session) { return session->is_closed(); }
                        ), sessions_.end()
                );
        }
        
    private:
        std::vector<std::shared_ptr<Session>> sessions_;
    };
}