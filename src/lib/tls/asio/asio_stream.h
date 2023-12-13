/*
* TLS ASIO Stream
* (C) 2018-2021 Jack Lloyd
*     2018-2021 Hannes Rantzsch, Tim Oesterreich, Rene Meusel
*     2023      Fabian Albert, René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ASIO_STREAM_H_
#define BOTAN_ASIO_STREAM_H_

#include <botan/asio_compat.h>
#if !defined(BOTAN_FOUND_COMPATIBLE_BOOST_ASIO_VERSION)
   #error Available boost headers are too old for the boost asio stream.
#else

   #include <botan/asio_async_ops.h>
   #include <botan/asio_context.h>
   #include <botan/asio_error.h>

   #include <botan/tls_callbacks.h>
   #include <botan/tls_channel.h>
   #include <botan/tls_client.h>
   #include <botan/tls_magic.h>
   #include <botan/tls_server.h>

   // We need to define BOOST_ASIO_DISABLE_SERIAL_PORT before any asio imports. Otherwise asio will include <termios.h>,
   // which interferes with Botan's amalgamation by defining macros like 'B0' and 'FF1'.
   #define BOOST_ASIO_DISABLE_SERIAL_PORT
   #include <boost/beast/core.hpp>
   #include <boost/container/devector.hpp>

   #include <algorithm>
   #include <memory>
   #include <type_traits>

namespace Botan::TLS {

template <class SL, class C>
class Stream;

/**
 * @brief Specialization of TLS::Callbacks for the ASIO Stream
 *
 * Applications may decide to derive from this for fine-grained customizations
 * of the TLS::Stream's behaviour. Examples may be OCSP integration, custom
 * certificate validation or user-defined key exchange mechanisms.
 *
 * By default, this class provides all necessary customizations for the ASIO
 * integration. The methods required for that are `final` and cannot be
 * overridden.
 *
 * Each instance of TLS::Stream must have their own instance of this class. A
 * future major version of Botan will therefor consume instances of this class
 * as a std::unique_ptr. The current usage of std::shared_ptr is erratic.
 */
class StreamCallbacksBase : public Callbacks {
   public:
      StreamCallbacksBase() = default;

      bool tls_peer_closed_connection() final {
         // Instruct the TLS implementation to reply with our close_notify to
         // obtain the same behaviour for TLS 1.2 and TLS 1.3. Currently, this
         // prevents a downstream application from closing their write-end while
         // allowing the peer to continue writing.
         //
         // When lifting this limitation, please take good note of the "Future
         // work" remarks in https://github.com/randombit/botan/pull/3801.
         return true;
      }

      /**
       * @param alert  a TLS alert sent by the peer
       */
      void tls_alert(TLS::Alert alert) final {
         if(alert.is_fatal() || alert.type() == TLS::AlertType::CloseNotify) {
            // TLS alerts received from the peer are not passed to the
            // downstream application immediately. Instead, we retain them here
            // and the stream invokes `handle_tls_protocol_errors()` in due time
            // to handle them.
            m_alert_from_peer = alert;
         }
      }

      void tls_verify_cert_chain(const std::vector<X509_Certificate>& cert_chain,
                                 const std::vector<std::optional<OCSP::Response>>& ocsp_responses,
                                 const std::vector<Certificate_Store*>& trusted_roots,
                                 Usage_Type usage,
                                 std::string_view hostname,
                                 const TLS::Policy& policy) override {
         auto ctx = m_context.lock();

         if(ctx && ctx->has_verify_callback()) {
            ctx->get_verify_callback()(cert_chain, ocsp_responses, trusted_roots, usage, hostname, policy);
         } else {
            Callbacks::tls_verify_cert_chain(cert_chain, ocsp_responses, trusted_roots, usage, hostname, policy);
         }
      }

   private:
      // The members below are meant for the tightly-coupled Stream class only
      template <class SL, class C>
      friend class Stream;

      void set_context(std::weak_ptr<Botan::TLS::Context> context) { m_context = std::move(context); }

      bool shutdown_received() const {
         return m_alert_from_peer && m_alert_from_peer->type() == AlertType::CloseNotify;
      }

      std::optional<Alert> alert_from_peer() const { return m_alert_from_peer; }

   private:
      std::optional<Alert> m_alert_from_peer;
      std::weak_ptr<TLS::Context> m_context;
};

class StreamCallbacksTLS : public StreamCallbacksBase {
      void tls_emit_data(std::span<const uint8_t> data) final {
         m_send_buffer.commit(boost::asio::buffer_copy(m_send_buffer.prepare(data.size()),
                                                       boost::asio::buffer(data.data(), data.size())));
      }

      void tls_record_received(uint64_t, std::span<const uint8_t> data) final {
         m_receive_buffer.commit(boost::asio::buffer_copy(m_receive_buffer.prepare(data.size()),
                                                          boost::asio::const_buffer(data.data(), data.size())));
      }

   public:
      StreamCallbacksTLS(size_t bufferSize = MAX_CIPHERTEXT_SIZE) : m_input_buffer(bufferSize) {}

      size_t available() const { return m_receive_buffer.size(); }

      size_t send_count_readable_bytes() const { return m_send_buffer.size(); }

      void consume_send_buffer(size_t bytes) { m_send_buffer.consume(bytes); }

      bool has_data_to_send() const { return m_send_buffer.size(); }

      bool has_received_data() const { return available(); }

      boost::asio::const_buffer send_buffer() const { return m_send_buffer.data(); }

      boost::asio::const_buffer receive_buffer_data() const { return m_receive_buffer.data(); }

      void consume_receive_buffer(size_t bytes) { m_receive_buffer.consume(bytes); }

      boost::asio::mutable_buffer input_buffer() { return boost::asio::buffer(m_input_buffer); }

   private:
      std::vector<uint8_t> m_input_buffer;  // Buffer used for receiving data (before decrypt)
      boost::beast::flat_buffer m_receive_buffer;
      boost::beast::flat_buffer m_send_buffer;
};

class StreamCallbacksDTLS : public StreamCallbacksBase {
      void tls_emit_data(std::span<const uint8_t> data) final {
         m_send_buffer.push_back(std::vector<uint8_t>(data.begin(), data.end()));
      }

      void tls_record_received(uint64_t, std::span<const uint8_t> data) final {
         m_receive_buffer.push_back(std::vector<uint8_t>(data.begin(), data.end()));
      }

   public:
      StreamCallbacksDTLS(size_t mtu = MAX_CIPHERTEXT_SIZE) : m_input_buffer(mtu) {}

      size_t available() const { return m_receive_buffer.empty() ? 0 : m_receive_buffer.front().size(); }

      size_t send_count_readable_bytes() const { return m_send_buffer.empty() ? 0 : m_send_buffer.front().size(); }

      void consume_send_buffer(size_t bytes) {
         // pop full messages
         size_t consumed = 0;
         while(bytes > consumed && !m_send_buffer.empty()) {
            consumed += m_send_buffer.front().size();
            m_send_buffer.pop_front();
         }
      }

      bool has_data_to_send() const { return !m_send_buffer.empty(); }

      bool has_received_data() const { return available(); }

      boost::asio::const_buffer send_buffer() const {
         return m_send_buffer.empty() ? boost::asio::const_buffer()
                                      : boost::asio::const_buffer(boost::asio::buffer(m_send_buffer.front()));
      }

      boost::asio::const_buffer receive_buffer_data() const {
         return m_receive_buffer.empty() ? boost::asio::const_buffer()
                                         : boost::asio::const_buffer(boost::asio::buffer(m_receive_buffer.front()));
      };

      void consume_receive_buffer(size_t bytes) {
         // pop full messages
         size_t consumed = 0;
         while(bytes > consumed && !m_receive_buffer.empty()) {
            consumed += m_receive_buffer.front().size();
            m_receive_buffer.pop_front();
         }
      }

      boost::asio::mutable_buffer input_buffer() { return boost::asio::buffer(m_input_buffer); }

   private:
      std::vector<uint8_t> m_input_buffer;  // Buffer used for receiving data (before decrypt)
      // deque has poor performance on some compilers, so we use devector instead
      boost::container::devector<std::vector<uint8_t>> m_receive_buffer;  // Decrypted data
      boost::container::devector<std::vector<uint8_t>> m_send_buffer;
};

namespace detail {

template <typename T>
concept basic_completion_token = boost::asio::completion_token_for<T, void(boost::system::error_code)>;

template <typename T>
concept byte_size_completion_token = boost::asio::completion_token_for<T, void(boost::system::error_code, size_t)>;

}  // namespace detail

/**
 * @brief boost::asio compatible SSL/TLS stream
 *
 * @tparam StreamLayer type of the next layer, usually a network socket
 * @tparam ChannelT type of the native_handle, defaults to TLS::Channel, only needed for testing purposes
 */
template <class StreamLayer, class ChannelT = Channel>
class Stream {
   private:
      using default_completion_token =
         boost::asio::default_completion_token_t<boost::beast::executor_type<StreamLayer>>;

   public:
      static constexpr bool m_is_dtls = !std::is_same_v<typename StreamLayer::protocol_type, boost::asio::ip::tcp>;
      using StreamCallbacksType = std::conditional_t<m_is_dtls, StreamCallbacksDTLS, StreamCallbacksTLS>;

      //! \name construction
      //! @{

      /**
       * @brief Construct a new Stream with a customizable instance of Callbacks
       *
       * @param context The context parameter is used to set up the underlying native handle.
       * @param callbacks The callbacks parameter may contain an instance of a derived TLS::Callbacks
       *                  class to allow for fine-grained customization of the TLS stream. Note that
       *                  applications need to ensure a 1-to-1 relationship between instances of
       *                  Callbacks and Streams. A future major version of Botan will use a unique_ptr
       *                  here.
       *
       * @param args Arguments to be forwarded to the construction of the next layer.
       */
      template <typename... Args>
      explicit Stream(std::shared_ptr<Context> context,
                      std::shared_ptr<StreamCallbacksType> callbacks,
                      Args&&... args) :
            m_context(std::move(context)), m_nextLayer(std::forward<Args>(args)...), m_core(std::move(callbacks)) {
         m_core->set_context(m_context);
      }

      /**
       * @brief Construct a new Stream
       *
       * @param context The context parameter is used to set up the underlying native handle.
       * @param args Arguments to be forwarded to the construction of the next layer.
       */
      template <typename... Args>
      explicit Stream(std::shared_ptr<Context> context, Args&&... args) :
            Stream(std::move(context), std::make_shared<StreamCallbacksType>(), std::forward<Args>(args)...) {}

      /**
       * @brief Construct a new Stream
       *
       * Convenience overload for boost::asio::ssl::stream compatibility.
       *
       * @param arg This argument is forwarded to the construction of the next layer.
       * @param context The context parameter is used to set up the underlying native handle.
       * @param callbacks The (optional) callbacks object that the stream should use. Note that
       *                  applications need to ensure a 1-to-1 relationship between instances of Callbacks
       *                  and Streams. A future major version of Botan will use a unique_ptr here.
       */
      template <typename Arg>
      explicit Stream(Arg&& arg,
                      std::shared_ptr<Context> context,
                      std::shared_ptr<StreamCallbacksType> callbacks = std::make_shared<StreamCallbacksType>()) :
            Stream(std::move(context), std::move(callbacks), std::forward<Arg>(arg)) {}

      virtual ~Stream() = default;

      Stream(Stream&& other) = default;
      Stream& operator=(Stream&& other) = default;

      Stream(const Stream& other) = delete;
      Stream& operator=(const Stream& other) = delete;

      //! @}
      //! \name boost::asio accessor methods
      //! @{

      using next_layer_type = typename std::remove_reference<StreamLayer>::type;

      const next_layer_type& next_layer() const { return m_nextLayer; }

      next_layer_type& next_layer() { return m_nextLayer; }

      using lowest_layer_type = typename boost::beast::lowest_layer_type<StreamLayer>;

      lowest_layer_type& lowest_layer() { return boost::beast::get_lowest_layer(m_nextLayer); }

      const lowest_layer_type& lowest_layer() const { return boost::beast::get_lowest_layer(m_nextLayer); }

      using executor_type = typename next_layer_type::executor_type;

      executor_type get_executor() noexcept { return m_nextLayer.get_executor(); }

      using native_handle_type = typename std::add_pointer<ChannelT>::type;

      native_handle_type native_handle() {
         BOTAN_STATE_CHECK(m_native_handle != nullptr);
         return m_native_handle.get();
      }

      const native_handle_type native_handle() const {
         if(m_native_handle == nullptr) {
            throw Invalid_State("Invalid handshake state");
         }
         return m_native_handle.get();
      }

      //! @}
      //! \name configuration and callback setters
      //! @{

      /**
       * @brief Override the tls_verify_cert_chain callback
       *
       * This changes the verify_callback in the stream's TLS::Context, and hence the tls_verify_cert_chain callback
       * used in the handshake.
       * Using this function is equivalent to setting the callback via @see Botan::TLS::Context::set_verify_callback
       *
       * @note This function should only be called before initiating the TLS handshake
       */
      void set_verify_callback(Context::Verify_Callback callback) {
         m_context->set_verify_callback(std::move(callback));
      }

      /**
       * @brief Compatibility overload of @ref set_verify_callback
       *
       * @param callback the callback implementation
       * @param ec This parameter is unused.
       */
      void set_verify_callback(Context::Verify_Callback callback, boost::system::error_code& ec) {
         BOTAN_UNUSED(ec);
         m_context->set_verify_callback(std::move(callback));
      }

      //! @throws Not_Implemented
      void set_verify_depth(int depth) {
         BOTAN_UNUSED(depth);
         throw Not_Implemented("set_verify_depth is not implemented");
      }

      /**
       * Not Implemented.
       * @param depth the desired verification depth
       * @param ec Will be set to `Botan::ErrorType::NotImplemented`
       */
      void set_verify_depth(int depth, boost::system::error_code& ec) {
         BOTAN_UNUSED(depth);
         ec = ErrorType::NotImplemented;
      }

      //! @throws Not_Implemented
      template <typename verify_mode>
      void set_verify_mode(verify_mode v) {
         BOTAN_UNUSED(v);
         throw Not_Implemented("set_verify_mode is not implemented");
      }

      /**
       * Not Implemented.
       * @param v the desired verify mode
       * @param ec Will be set to `Botan::ErrorType::NotImplemented`
       */
      template <typename verify_mode>
      void set_verify_mode(verify_mode v, boost::system::error_code& ec) {
         BOTAN_UNUSED(v);
         ec = ErrorType::NotImplemented;
      }

      //! @}
      //! \name handshake methods
      //! @{

      /**
       * @brief Performs SSL handshaking.
       *
       * The function call will block until handshaking is complete or an error occurs.
       *
       * @param side The type of handshaking to be performed, i.e. as a client or as a server.
       * @throws boost::system::system_error if error occured
       */
      void handshake(Connection_Side side) {
         boost::system::error_code ec;
         handshake(side, ec);
         boost::asio::detail::throw_error(ec, "handshake");
      }

      /**
       * @brief Performs SSL handshaking.
       *
       * The function call will block until handshaking is complete or an error occurs.
       *
       * @param side The type of handshaking to be performed, i.e. as a client or as a server.
       * @param ec Set to indicate what error occurred, if any.
       */
      void handshake(Connection_Side side, boost::system::error_code& ec) {
         setup_native_handle(side, ec);

         // We write to the socket if we have data to send and read from it
         // otherwise, until either some error occured or we have successfully
         // performed the handshake.
         while(!ec) {
            // Send pending data to the peer and abort the handshake if that
            // fails with a network error. We do that first, to allow sending
            // any final message before reporting the handshake as "finished".
            if(has_data_to_send()) {
               send_pending_encrypted_data(ec);
            }

            // Once the underlying TLS implementation reports a complete and
            // successful handshake we're done.
            if(native_handle()->is_handshake_complete()) {
               return;
            }

            // Handle and report any TLS protocol errors that might have
            // surfaced in a previous iteration. By postponing their handling we
            // allow the stream to send a respective TLS alert to the peer before
            // aborting the handshake.
            handle_tls_protocol_errors(ec);

            // If we don't have any encrypted data to send we attempt to read
            // more data from the peer. This reports network errors immediately.
            // TLS protocol errors result in an internal state change which is
            // handled by `handle_tls_protocol_errors()` in the next iteration.
            read_and_process_encrypted_data_from_peer(ec);
         }

         BOTAN_ASSERT_NOMSG(ec.failed());
      }

      /**
       * @brief Starts an asynchronous SSL handshake.
       *
       * This function call always returns immediately.
       *
       * @param side The type of handshaking to be performed, i.e. as a client or as a server.
       * @param completion_token The completion handler to be called when the handshake operation completes.
       *                         The completion signature of the handler must be: void(boost::system::error_code).
       */
      template <detail::basic_completion_token CompletionToken = default_completion_token>
      auto async_handshake(Botan::TLS::Connection_Side side,
                           CompletionToken&& completion_token = default_completion_token{}) {
         return boost::asio::async_initiate<CompletionToken, void(boost::system::error_code)>(
            [this]<typename CallbackType>(CallbackType&& completion_handler, TLS::Connection_Side connection_side) {
               boost::system::error_code ec;
               setup_native_handle(connection_side, ec);
               boost::asio::co_spawn(
                  get_executor(),
                  [this]() mutable -> boost::asio::awaitable<boost::system::error_code> {
                     if constexpr(m_is_dtls) {
                        boost::asio::steady_timer handshake_max_time_guard{get_executor()};
                        handshake_max_time_guard.expires_after(std::chrono::seconds{6});
                        using namespace boost::asio::experimental::awaitable_operators;
                        std::variant<boost::system::error_code, std::monostate> handshake_result =
                           co_await (detail::async_handshake_awaitable_dtls<Stream>(*this) ||
                                     handshake_max_time_guard.async_wait(boost::asio::use_awaitable));
                        if(handshake_result.index() == 0) {
                           co_return std::get<0>(handshake_result);
                        } else {
                           co_return boost::system::error_code{boost::asio::error::timed_out};
                        }
                     } else {
                        co_return co_await detail::async_handshake_awaitable<Stream>(*this);
                     }
                  },
                  [completion_handler = std::forward<CallbackType>(completion_handler)](
                     std::exception_ptr eptr, const boost::system::error_code& ec) {
                     boost::system::error_code tmp_code = ec;
                     if(eptr) {
                        try {
                        } catch(boost::system::system_error& e) {
                           tmp_code = e.code();
                        } catch(...) {
                           std::rethrow_exception(eptr);
                        }
                     }
                     completion_handler(tmp_code);
                  });
            },
            completion_token,
            side);
      }

      //! @throws Not_Implemented
      template <typename ConstBufferSequence, detail::basic_completion_token BufferedHandshakeHandler>
      auto async_handshake(Connection_Side side,
                           const ConstBufferSequence& buffers,
                           BufferedHandshakeHandler&& handler) {
         BOTAN_UNUSED(side, buffers, handler);
         throw Not_Implemented("buffered async handshake is not implemented");
      }

      //! @}
      //! \name shutdown methods
      //! @{

      /**
       * @brief Shut down SSL on the stream.
       *
       * This function is used to shut down SSL on the stream. The function call will block until SSL has been shut down
       * or an error occurs. Note that this will not close the lowest layer.
       *
       * Note that this can be used in reaction of a received shutdown alert from the peer.
       *
       * @param ec Set to indicate what error occured, if any.
       */
      void shutdown(boost::system::error_code& ec) {
         try_with_error_code([&] { native_handle()->close(); }, ec);

         send_pending_encrypted_data(ec);
      }

      /**
       * @brief Shut down SSL on the stream.
       *
       * This function is used to shut down SSL on the stream. The function call will block until SSL has been shut down
       * or an error occurs. Note that this will not close the lowest layer.
       *
       * Note that this can be used in reaction of a received shutdown alert from the peer.
       *
       * @throws boost::system::system_error if error occured
       */
      void shutdown() {
         boost::system::error_code ec;
         shutdown(ec);
         boost::asio::detail::throw_error(ec, "shutdown");
      }

      size_t available() const { return m_core->available(); }

      // TODO: should return error?
      size_t available(boost::system::error_code& /*ec*/) const { return m_core->available(); }

   private:
      /**
       * @brief Internal wrapper type to adapt the expected signature of `async_shutdown` to the completion handler
       *        signature of `AsyncWriteOperation`.
       *
       * This is boilerplate to ignore the `size_t` parameter that is passed to the completion handler of
       * `AsyncWriteOperation`. Note that it needs to retain the wrapped handler's executor.
       */
      template <typename Handler, typename Executor>
      struct Wrapper {
            void operator()(boost::system::error_code ec, std::size_t) { handler(ec); }

            using executor_type = boost::asio::associated_executor_t<Handler, Executor>;

            executor_type get_executor() const noexcept {
               return boost::asio::get_associated_executor(handler, io_executor);
            }

            using allocator_type = boost::asio::associated_allocator_t<Handler>;

            allocator_type get_allocator() const noexcept { return boost::asio::get_associated_allocator(handler); }

            Handler handler;
            Executor io_executor;
      };

   public:
      /**
       * @brief Asynchronously shut down SSL on the stream.
       *
       * This function call always returns immediately.
       *
       * Note that this can be used in reaction of a received shutdown alert from the peer.
       *
       * @param completion_token The completion handler to be called when the shutdown operation completes.
       *                         The completion signature of the handler must be: void(boost::system::error_code).
       */
      template <detail::basic_completion_token CompletionToken = default_completion_token>
      auto async_shutdown(CompletionToken&& completion_token = default_completion_token{}) {
         return boost::asio::async_initiate<CompletionToken, void(boost::system::error_code)>(
            [this](auto&& completion_handler) {
               using completion_handler_t = std::decay_t<decltype(completion_handler)>;

               boost::system::error_code ec;
               try_with_error_code([&] { native_handle()->close(); }, ec);

               using write_handler_t = Wrapper<completion_handler_t, typename Stream::executor_type>;

               TLS::detail::AsyncWriteOperation<write_handler_t, Stream> op{
                  write_handler_t{std::forward<completion_handler_t>(completion_handler), get_executor()},
                  *this,
                  boost::asio::buffer_size(send_buffer()),
                  ec};
            },
            completion_token);
      }

      //! @}
      //! \name I/O methods
      //! @{

      /**
       * @brief Read some data from the stream.
       *
       * The function call will block until one or more bytes of data has been read successfully, or until an error
       * occurs.
       *
       * @param buffers The buffers into which the data will be read.
       * @param ec Set to indicate what error occurred, if any. Specifically, StreamTruncated will be set if the peer
       *           has closed the connection but did not properly shut down the SSL connection.
       * @return The number of bytes read. Returns 0 if an error occurred.
       */
      template <typename MutableBufferSequence>
      std::size_t read_some(const MutableBufferSequence& buffers, boost::system::error_code& ec) {
         if(has_received_data()) {
            return copy_received_data(buffers);
         }
         size_t bytes_read = m_nextLayer.read_some(input_buffer(), ec);
         boost::asio::const_buffer read_buffer(input_buffer().data(), bytes_read);
         if(ec) {
            return 0;
         }

         // We read from the socket until either some error occured or we have
         // decrypted at least one byte of application data.
         while(!ec) {
            // Some previous invocation of process_encrypted_data() generated
            // application data in the output buffer that can now be returned.
            if(has_received_data()) {
               return copy_received_data(buffers);
            }

            // Handle and report any TLS protocol errors (including a
            // close_notify) that might have surfaced in a previous iteration
            // (in `read_and_process_encrypted_data_from_peer()`). This makes
            // sure that all received application data was handed out to the
            // caller before reporting an error (e.g. EOF at the end of the
            // stream).
            handle_tls_protocol_errors(ec);

            // If we don't have any plaintext application data, yet, we attempt
            // to read more data from the peer. This reports network errors
            // immediately. TLS protocol errors result in an internal state
            // change which is handled by `handle_tls_protocol_errors()` in the
            // next iteration.
            read_and_process_encrypted_data_from_peer(ec);
         }

         BOTAN_ASSERT_NOMSG(ec.failed());
         return 0;
      }

      /**
       * @brief Read some data from the stream.
       *
       * The function call will block until one or more bytes of data has been read successfully, or until an error
       * occurs.
       *
       * @param buffers The buffers into which the data will be read.
       * @return The number of bytes read. Returns 0 if an error occurred.
       * @throws boost::system::system_error if error occured
       */
      template <typename MutableBufferSequence>
      std::size_t read_some(const MutableBufferSequence& buffers) {
         boost::system::error_code ec;
         const auto n = read_some(buffers, ec);
         boost::asio::detail::throw_error(ec, "read_some");
         return n;
      }

      /**
       * @brief Write some data to the stream.
       *
       * The function call will block until one or more bytes of data has been written successfully, or until an error
       * occurs.
       *
       * @param buffers The data to be written.
       * @param ec Set to indicate what error occurred, if any.
       * @return The number of bytes processed from the input buffers.
       */
      template <typename ConstBufferSequence>
      std::size_t write_some(const ConstBufferSequence& buffers, boost::system::error_code& ec) {
         tls_encrypt(buffers, ec);
         send_pending_encrypted_data(ec);
         return !ec ? boost::asio::buffer_size(buffers) : 0;
      }

      /**
       * @brief Write some data to the stream.
       *
       * The function call will block until one or more bytes of data has been written successfully, or until an error
       * occurs.
       *
       * @param buffers The data to be written.
       * @return The number of bytes written.
       * @throws boost::system::system_error if error occured
       */
      template <typename ConstBufferSequence>
      std::size_t write_some(const ConstBufferSequence& buffers) {
         boost::system::error_code ec;
         const auto n = write_some(buffers, ec);
         boost::asio::detail::throw_error(ec, "write_some");
         return n;
      }

      /**
       * @brief Start an asynchronous write. The function call always returns immediately.
       *
       * @param buffers The data to be written.
       * @param completion_token The completion handler to be called when the write operation completes. Copies of the
       *                         handler will be made as required. The completion signature of the handler must be:
       *                         void(boost::system::error_code, std::size_t).
       */
      template <typename ConstBufferSequence,
                detail::byte_size_completion_token CompletionToken = default_completion_token>
      auto async_write_some(const ConstBufferSequence& buffers,
                            CompletionToken&& completion_token = default_completion_token{}) {
         return boost::asio::async_initiate<CompletionToken, void(boost::system::error_code, std::size_t)>(
            [this](auto&& completion_handler, const auto& bufs) {
               using completion_handler_t = std::decay_t<decltype(completion_handler)>;

               boost::system::error_code ec;
               tls_encrypt(bufs, ec);

               if(ec) {
                  // we cannot be sure how many bytes were committed here so clear the send_buffer and let the
                  // AsyncWriteOperation call the handler with the error_code set
                  consume_send_buffer(m_core->send_count_readable_bytes());
               }

               detail::AsyncWriteOperation<completion_handler_t, Stream> op{
                  std::forward<completion_handler_t>(completion_handler),
                  *this,
                  ec ? 0 : boost::asio::buffer_size(bufs),
                  ec};
            },
            completion_token,
            buffers);
      }

      /**
       * @brief Start an asynchronous read. The function call always returns immediately.
       *
       * @param buffers The buffers into which the data will be read. Although the buffers object may be copied as
       *                necessary, ownership of the underlying buffers is retained by the caller, which must guarantee
       *                that they remain valid until the handler is called.
       * @param completion_token The completion handler to be called when the read operation completes. The completion
       *                         signature of the handler must be: void(boost::system::error_code, std::size_t).
       */
      template <typename MutableBufferSequence,
                detail::byte_size_completion_token CompletionToken = default_completion_token>
      auto async_read_some(const MutableBufferSequence& buffers,
                           CompletionToken&& completion_token = default_completion_token{}) {
         return boost::asio::async_initiate<CompletionToken, void(boost::system::error_code, std::size_t)>(
            [this](auto&& completion_handler, const auto& bufs) {
               using completion_handler_t = std::decay_t<decltype(completion_handler)>;

               detail::AsyncReadOperation<completion_handler_t, Stream, MutableBufferSequence> op{
                  std::forward<completion_handler_t>(completion_handler), *this, bufs};
            },
            completion_token,
            buffers);
      }

      //! @}

      //! @brief Indicates whether a close_notify alert has been received from the peer.
      //!
      //! Note that we cannot m_core.is_closed_for_reading() because this wants to
      //! explicitly check that the peer sent close_notify.
      bool shutdown_received() const { return m_core->shutdown_received(); }

   protected:
      template <class H, class S, class M, class A>
      friend class detail::AsyncReadOperation;
      template <class H, class S, class A>
      friend class detail::AsyncWriteOperation;

      friend boost::asio::awaitable<boost::system::error_code> detail::async_handshake_awaitable_dtls<Stream>(
         Stream& stream);

      friend boost::asio::awaitable<boost::system::error_code> detail::async_handshake_awaitable<Stream>(
         Stream& stream);

      friend boost::asio::awaitable<std::pair<size_t, boost::system::error_code>>
      detail::async_write_some_awaitable<Stream>(Stream& stream);

      boost::asio::mutable_buffer input_buffer() { return m_core->input_buffer(); }

      boost::asio::const_buffer send_buffer() const { return m_core->send_buffer(); }

      //! @brief Check if decrypted data is available in the receive buffer
      bool has_received_data() const { return m_core->has_received_data(); }

      //! @brief Copy decrypted data into the user-provided buffer
      template <typename MutableBufferSequence>
      std::size_t copy_received_data(MutableBufferSequence buffers) {
         // Note: It would be nice to avoid this buffer copy. This could be achieved by equipping the CallbacksT with
         // the user's desired target buffer once a read is started, and reading directly into that buffer in tls_record
         // received. However, we need to deal with the case that the receive buffer provided by the caller is smaller
         // than the decrypted record, so this optimization might not be worth the additional complexity.
         const auto copiedBytes = boost::asio::buffer_copy(buffers, m_core->receive_buffer_data());
         m_core->consume_receive_buffer(copiedBytes);
         return copiedBytes;
      }

      //! @brief Check if encrypted data is available in the send buffer
      bool has_data_to_send() const { return m_core->has_data_to_send() > 0; }

      //! @brief Mark bytes in the send buffer as consumed, removing them from the buffer
      void consume_send_buffer(std::size_t bytesConsumed) { m_core->consume_send_buffer(bytesConsumed); }

      //! @brief Mark bytes in the receive buffer as consumed, removing them from the buffer
      void consume_receive_buffer(std::size_t bytesConsumed) { m_core->consume_receive_buffer(bytesConsumed); }

      /**
       * @brief Create the native handle.
       *
       * Depending on the desired connection side, this function will create a TLS::Client or a
       * TLS::Server.
       *
       * @param side The desired connection side (client or server)
       * @param ec Set to indicate what error occurred, if any.
       */
      void setup_native_handle(Connection_Side side, boost::system::error_code& ec) {
         // Do not attempt to instantiate the native_handle when a custom (mocked) channel type template parameter has
         // been specified. This allows mocking the native_handle in test code.
         if constexpr(std::is_same<ChannelT, Channel>::value) {
            BOTAN_STATE_CHECK(m_native_handle == nullptr);

            try_with_error_code(
               [&] {
                  if(side == Connection_Side::Client) {
                     m_native_handle =
                        std::unique_ptr<Client>(new Client(m_core,
                                                           m_context->m_session_manager,
                                                           m_context->m_credentials_manager,
                                                           m_context->m_policy,
                                                           m_context->m_rng,
                                                           m_context->m_server_info,
                                                           m_context->m_policy->latest_supported_version(m_is_dtls)));
                  } else {
                     m_native_handle = std::unique_ptr<Server>(new Server(m_core,
                                                                          m_context->m_session_manager,
                                                                          m_context->m_credentials_manager,
                                                                          m_context->m_policy,
                                                                          m_context->m_rng,
                                                                          m_is_dtls));
                  }
               },
               ec);
         }
      }

      /**
       * The `Stream` has to distinguish from network-related issues (that are
       * reported immediately) from TLS protocol errors, that must be retained
       * and emitted once all legal application traffic received before is
       * pushed to the downstream application.
       *
       * See also `process_encrypted_data()` and `StreamCallbacks::tls_alert()`
       * where those TLS protocol errors are detected and retained for eventual
       * handling in this method.
       *
       * See also https://github.com/randombit/botan/pull/3801 for a detailed
       * description of the ASIO stream's state management.
       *
       * @param ec  this error code is set if we previously detected a TLS
       *            protocol error.
       */
      void handle_tls_protocol_errors(boost::system::error_code& ec) {
         if(ec) {
            return;
         }

         // If we had raised an error while processing TLS records received from
         // the peer, we expose that error here.
         //
         // See also `process_encrypted_data()`.
         else if(auto error = error_from_us()) {
            ec = error;
         }

         // If we had received a TLS alert from the peer, we expose that error
         // here. See also `StreamCallbacks::tls_alert()` where such alerts
         // would be detected and retained initially.
         //
         // Note that a close_notify is always a legal way for the peer to end a
         // TLS session. When received during the handshake it typically means
         // that the peer wanted to cancel the handshake for some reason not
         // related to the TLS protocol.
         else if(auto alert = alert_from_peer()) {
            if(alert->type() == AlertType::CloseNotify) {
               ec = boost::asio::error::eof;
            } else {
               ec = alert->type();
            }
         }
      }

      /**
       * Reads TLS record data from the peer and forwards it to the native
       * handle for processing. Note that @p ec will reflect network errors
       * only. Any detected or received TLS protocol errors will be retained and
       * must be handled by the downstream operation in due time by invoking
       * `handle_tls_protocol_errors()`.
       *
       * @param ec  this error code might be populated with network-related errors
       */
      void read_and_process_encrypted_data_from_peer(boost::system::error_code& ec) {
         if(ec) {
            return;
         }

         // If we have received application data in a previous invocation, this
         // data needs to be passed to the application first. Otherwise, it
         // might get overwritten.
         BOTAN_ASSERT(!has_received_data(), "receive buffer is empty");
         BOTAN_ASSERT(!error_from_us() && !alert_from_peer(), "TLS session is healthy");

         // If there's no existing error condition, read and process data from
         // the peer and report any sort of network error. TLS related errors do
         // not immediately cause an abort, they are checked in the invocation
         // via `error_from_us()`.
         boost::asio::const_buffer read_buffer{input_buffer().data(), m_nextLayer.read_some(input_buffer(), ec)};
         if(!ec) {
            process_encrypted_data(read_buffer);
         } else if(ec == boost::asio::error::eof) {
            ec = StreamError::StreamTruncated;
         }
      }

      /** @brief Synchronously write encrypted data from the send buffer to the next layer.
       *
       * If this function is called with an error code other than 'Success', it will do nothing and return 0.
       *
       * @param ec Set to indicate what error occurred, if any. Specifically, StreamTruncated will be set if the peer
       *           has closed the connection but did not properly shut down the SSL connection.
       * @return The number of bytes written.
       */
      size_t send_pending_encrypted_data(boost::system::error_code& ec) {
         if(ec) {
            return 0;
         }

         auto writtenBytes = boost::asio::write(m_nextLayer, send_buffer(), ec);
         consume_send_buffer(writtenBytes);

         if(ec == boost::asio::error::eof && !shutdown_received()) {
            // transport layer was closed by peer without receiving 'close_notify'
            ec = StreamError::StreamTruncated;
         }

         return writtenBytes;
      }

      /**
       * @brief Pass plaintext data to the native handle for processing.
       *
       * The native handle will then create TLS records and hand them back to the Stream via the tls_emit_data callback.
       */
      template <typename ConstBufferSequence>
      void tls_encrypt(const ConstBufferSequence& buffers, boost::system::error_code& ec) {
         // NOTE: This is not asynchronous: it encrypts the data synchronously.
         // The data encrypted by native_handle()->send() is synchronously stored in the send_buffer of m_core,
         // but is not actually written to the wire, yet.
         for(auto it = boost::asio::buffer_sequence_begin(buffers);
             !ec && it != boost::asio::buffer_sequence_end(buffers);
             it++) {
            const boost::asio::const_buffer buffer = *it;
            try_with_error_code(
               [&] {
                  native_handle()->send({static_cast<const uint8_t*>(buffer.data()), buffer.size()});
               },
               ec);
         }
      }

      /**
       * Pass encrypted data received from the peer to the native handle for
       * processing. If the @p read_buffer contains coalesced TLS records, this
       * might result in multiple TLS protocol state changes.
       *
       * To allow the ASIO stream wrapper to disentangle those state changes
       * properly, any TLS protocol errors are retained and must be handled by
       * calling `handle_tls_protocol_errors()` in due time.
       *
       * @param read_buffer Input buffer containing the encrypted data.
       */
      void process_encrypted_data(const boost::asio::const_buffer& read_buffer) {
         BOTAN_ASSERT(!alert_from_peer() && !error_from_us(),
                      "no one sent an alert before (no data allowed after that)");

         // If the local TLS implementation generates an alert, we are notified
         // with an exception that is caught in try_with_error_code(). The error
         // code is retained and not handled directly. Stream operations will
         // have to invoke `handle_tls_protocol_errors()` to handle them later.
         try_with_error_code(
            [&] {
               native_handle()->received_data({static_cast<const uint8_t*>(read_buffer.data()), read_buffer.size()});
            },
            m_ec_from_last_read);
      }

      //! @brief Catch exceptions and set an error_code
      template <typename Fun>
      void try_with_error_code(Fun f, boost::system::error_code& ec) {
         try {
            f();
         } catch(const TLS_Exception& e) {
            ec = e.type();
         } catch(const Exception& e) {
            ec = e.error_type();
         } catch(const std::exception&) {
            ec = ErrorType::Unknown;
         }
      }

   private:
      /**
       * Returns any alert previously received from the peer. This may include
       * close_notify. Once the peer has sent any alert, no more data must be
       * read from the stream.
       */
      std::optional<Alert> alert_from_peer() const { return m_core->alert_from_peer(); }

      /**
       * Returns any error code produced by the local TLS implementation. This
       * will _not_ include close_notify. Once our TLS stack has reported an
       * error, no more data must be written to the stream. The peer will receive
       * the error as a TLS alert.
       */
      boost::system::error_code error_from_us() const { return m_ec_from_last_read; }

   protected:
      std::shared_ptr<Context> m_context;
      StreamLayer m_nextLayer;

      std::shared_ptr<StreamCallbacksType> m_core;
      std::unique_ptr<ChannelT> m_native_handle;
      boost::system::error_code m_ec_from_last_read;

      // Buffer space used to read input intended for the core
      std::vector<uint8_t> m_input_buffer_space;
      const boost::asio::mutable_buffer m_input_buffer;
};

}  // namespace Botan::TLS

#endif
#endif  // BOTAN_ASIO_STREAM_H_
