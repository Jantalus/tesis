class FileFlushStreamBuf : public std::streambuf {
public:
    FileFlushStreamBuf() : max_size_(1'000'000) {
        buffer_.reserve(max_size_);
    }

    FileFlushStreamBuf(const std::string& file_path, size_t max_size)
        : buffer_(), file_(file_path, std::ios::out | std::ios::binary), max_size_(max_size) {
        if (!file_.is_open()) {
            std::cerr << "Failed to open file: " + file_path << std::endl;
        }
        buffer_.reserve(max_size);
    }

    // Move assignment operator
    FileFlushStreamBuf& operator=(FileFlushStreamBuf&& other) noexcept {
        if (this != &other) {
            sync(); // Flush current buffer
            if (file_.is_open()) {
                file_.close();
            }
            buffer_ = std::move(other.buffer_);
            file_ = std::move(other.file_); // Note: std::ofstream move is C++11+ but may require care
            max_size_ = other.max_size_;
            other.buffer_.clear();
            other.max_size_ = 0;
            if (other.file_.is_open()) {
                other.file_.close();
            }
        }
        return *this;
    }

    void open_file(const std::string& file_path, size_t max_size) {
        if (file_.is_open()) {
            sync();
            file_.close();
        }
        file_.open(file_path, std::ios::out | std::ios::binary);
        if (!file_.is_open()) {
            std::cerr << "Failed to open file: " + file_path << std::endl;
        }
        max_size_ = max_size;
        buffer_.clear();
        buffer_.reserve(max_size);
    }

    int sync() override {
        if (!buffer_.empty() && file_.is_open()) {
            file_.write(buffer_.data(), buffer_.size());
            if (!file_) {
                return -1;
            }
            buffer_.clear();
            buffer_.reserve(max_size_);
        }
        if (file_.is_open()) {
            file_.flush();
        }
        return file_.is_open() ? (file_ ? 0 : -1) : 0;
    }

    ~FileFlushStreamBuf() override {
        sync();
        file_.close();
    }

protected:
    int_type overflow(int_type c) override {
        if (c != EOF) {
            buffer_.push_back(static_cast<char>(c));
            if (buffer_.size()/16 >= max_size_) {
                sync();
            }
        }
        return c;
    }


private:
    std::string buffer_;
    std::ofstream file_;
    size_t max_size_;
};

class FileFlushOStream : public std::ostream {
public:
    FileFlushOStream() : std::ostream(&buf_), buf_() {}

    FileFlushOStream(const std::string& file_path, size_t max_size)
        : std::ostream(&buf_), buf_(file_path, max_size) {}

    void open(const std::string& file_path, size_t max_size) {
        buf_.open_file(file_path, max_size);
    }

    // Move assignment operator
    FileFlushOStream& operator=(FileFlushOStream&& other) noexcept {
        if (this != &other) {
            // Flush current buffer to avoid data loss
            buf_.sync();
            // Move the underlying streambuf
            buf_ = std::move(other.buf_);
            // Update the ostream's streambuf pointer
            this->rdbuf(&buf_);
            // Clear the other ostream's state to prevent issues
            other.setstate(std::ios::badbit);
        }
        return *this;
    }

private:
    FileFlushStreamBuf buf_;
};