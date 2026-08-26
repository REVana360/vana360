#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <thread>

#include <rex/runtime.h>

class RevanaLobbyBridge
{
public:
    RevanaLobbyBridge()                                    = default;
    RevanaLobbyBridge(const RevanaLobbyBridge&)            = delete;
    RevanaLobbyBridge& operator=(const RevanaLobbyBridge&) = delete;

    bool                    Configure(rex::RuntimeConfig& config);
    std::optional<uint32_t> configured_ipv4() const;
    void                    StartStateTrace(rex::Runtime* runtime);
    void                    StopStateTrace();

private:
    struct State;
    std::shared_ptr<State> state_;
    std::jthread           data_thread_;
    std::jthread           state_trace_thread_;
    bool                   state_trace_enabled_ = false;
};
