#include <iostream>
#include <cstdarg>

void log_error(const char* message, ...) {
    va_list args{};
    va_start(args, message);
    std::cerr << "[\033[31m!\033[0m] ";//red
    std::vprintf(message, args);
    std::cerr << std::endl;
    va_end(args);
}

void log_info(const char* message, ...) {
    va_list args{};
    va_start(args, message);
    std::cout << "[\033[34m*\033[0m] ";//blue
    std::vprintf(message, args);
    std::cout << std::endl;
    va_end(args);
}

void log_verbose(const char* message, ...) {
    va_list args{};
    va_start(args, message);
    std::cout << "[\033[90m#\033[0m] ";//gray
    std::vprintf(message, args);
    std::cout << std::endl;
    va_end(args);
}

void log_success(const char* message, ...) {
    va_list args{};
    va_start(args, message);
    std::cout << "[\033[32m+\033[0m] ";//green
    std::vprintf(message, args);
    std::cout << std::endl;
    va_end(args);
}
