#pragma once

#ifdef _WIN32
#include "socket-detail-win.hpp"
#else
#include "socket-detail-posix.hpp"
#endif