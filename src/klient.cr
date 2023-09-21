class Klient
  VERSION = "0.1.0"

  def initialize(host, port = 443)
    context = OpenSSL::SSL::Context::Client.new
    context.verify_mode = OpenSSL::SSL::VerifyMode::NONE

    @tcp_socket = TCPSocket.new(host, port)
    @tcp_socket.sync = false

    @ssl_socket = OpenSSL::SSL::Socket::Client.new(
      @tcp_socket,
      context: context,
      hostname: host
    )
  end

  def <<(data : String | Nil)
    @ssl_socket << data << "\r\n"
  end

  def send
    @ssl_socket.flush
  end

  def status
    line = @ssl_socket.gets("\r\n")

    raise "unknown status line" if line.nil?

    line[9, 3]
  end

  def headers(headers)
    results = Array(String | Nil).new(headers.size, nil)

    while true
      line = @ssl_socket.gets("\r\n", chomp: true)
      break if line.nil? || line.empty?

      headers.each_with_index do |header, index|
        if line.starts_with?(header)
          results[index] = line[(header.size + 2)..-1].strip
        end
      end
    end

    results
  end

  def body(length : Int32)
    @ssl_socket.read_string(length)
  end

  def finalize
    @tcp_socket.close
    @ssl_socket.close
  end
end
