/*
* TLS ASIO Stream
* (C) 2018-2020 Jack Lloyd
*     2018-2020 Hannes Rantzsch, Tim Oesterreich, Rene Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ASIO_STREAM_H_
#define BOTAN_ASIO_STREAM_H_

#include <botan/build.h>

// first version to be compatible with Networking TS (N4656) and boost::beast
#include <boost/version.hpp>

#if BOOST_VERSION >= 106600

#include <botan/asio_async_ops.h>
#include <botan/asio_context.h>
#include <botan/asio_error.h>
#include <botan/asio_op_wrappers.h>

#include <botan/tls_callbacks.h>
#include <botan/tls_channel.h>
#include <botan/tls_client.h>
#include <botan/tls_magic.h>
#include <botan/tls_server.h>

// We need to define BOOST_ASIO_DISABLE_SERIAL_PORT before any asio imports. Otherwise asio will include <termios.h>,
// which interferes with Botan's amalgamation by defining macros like 'B0' and 'FF1'.
#define BOOST_ASIO_DISABLE_SERIAL_PORT

#include <boost/asio.hpp>
#include <boost/beast/core.hpp>

#include <algorithm>
#include <memory>
#include <type_traits>

namespace Botan {
namespace TLS {

/**
 * @brief boost::asio compatible SSL/TLS stream
 *
 * @tparam StreamLayer type of the next layer, usually a network socket
 * @tparam ChannelT type of the native_handle, defaults to Botan::TLS::Channel, only needed for testing purposes
 */
template<class StreamLayer, bool DTLS = false, class ChannelT = Channel>
class Stream
   {
   public:
      using SocketType = StreamLayer;

      //! \name construction
      //! @{

      /**
       * @brief Construct a new Stream
       *
       * @param context The context parameter is used to set up the underlying native handle. Using code is
       *                responsible for lifetime management of the context and must ensure that it is available for the
       *                lifetime of the stream.
       * @param args Arguments to be forwarded to the construction of the next layer.
       */
      template<typename... Args>
      explicit Stream(Context& context, Args&& ... args)
         : m_context(context)
         , m_nextLayer(std::forward<Args>(args)...)
         , m_core(*this)
         , m_shutdown_received(false)
         , m_input_buffer_space(MAX_CIPHERTEXT_SIZE, '\0')
         , m_input_buffer(m_input_buffer_space.data(), m_input_buffer_space.size())
         {}

      /**
       * @brief Construct a new Stream
       *
       * Convenience overload for boost::asio::ssl::stream compatibility.
       *
       * @param arg This argument is forwarded to the construction of the next layer.
       * @param context The context parameter is used to set up the underlying native handle. Using code is
       *                responsible for lifetime management of the context and must ensure that is available for the
       *                lifetime of the stream.
       */
      template<typename Arg>
      explicit Stream(Arg&& arg, Context& context)
         : m_context(context)
         , m_nextLayer(std::forward<Arg>(arg))
         , m_core(*this)
         , m_shutdown_received(false)
         , m_input_buffer_space(MAX_CIPHERTEXT_SIZE, '\0')
         , m_input_buffer(m_input_buffer_space.data(), m_input_buffer_space.size())
         {}

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

#if BOOST_VERSION >= 107000
      /*
       * From Boost 1.70 onwards Beast types no longer provide public access to the member function `lowest_layer()`.
       * Instead, the new free-standing functions in Beast need to be used.
       * See also: https://github.com/boostorg/beast/commit/6a658b5c3a36f8d58334f8b6582c01c3e87768ae
       */
      using lowest_layer_type = typename boost::beast::lowest_layer_type<StreamLayer>;

      lowest_layer_type& lowest_layer() { return boost::beast::get_lowest_layer(m_nextLayer); }
      const lowest_layer_type& lowest_layer() const { return boost::beast::get_lowest_layer(m_nextLayer); }
#else
      using lowest_layer_type = typename next_layer_type::lowest_layer_type;

      lowest_layer_type& lowest_layer() { return m_nextLayer.lowest_layer(); }
      const lowest_layer_type& lowest_layer() const { return m_nextLayer.lowest_layer(); }
#endif

      using executor_type = typename next_layer_type::executor_type;
      executor_type get_executor() noexcept { return m_nextLayer.get_executor(); }

      using native_handle_type = typename std::add_pointer<ChannelT>::type;
      native_handle_type native_handle()
         {
         if(m_native_handle == nullptr)
            { throw Invalid_State("Invalid handshake state"); }
         return m_native_handle.get();
         }


      size_t available() const
         {
         return m_receive_buffer.size();
         }

      size_t available(boost::system::error_code&) const
         {
         return m_receive_buffer.size();
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
      void set_verify_callback(Context::Verify_Callback callback)
         {
         m_context.set_verify_callback(std::move(callback));
         }

      /**
       * @brief Compatibility overload of @ref set_verify_callback
       *
       * @param ec This parameter is unused.
       */
      void set_verify_callback(Context::Verify_Callback callback, boost::system::error_code& ec)
         {
         BOTAN_UNUSED(ec);
         m_context.set_verify_callback(std::move(callback));
         }

      //! @throws Not_Implemented
      void set_verify_depth(int depth)
         {
         BOTAN_UNUSED(depth);
         throw Not_Implemented("set_verify_depth is not implemented");
         }

      /**
       * Not Implemented.
       * @param ec Will be set to `Botan::ErrorType::NotImplemented`
       */
      void set_verify_depth(int depth, boost::system::error_code& ec)
         {
         BOTAN_UNUSED(depth);
         ec = Botan::ErrorType::NotImplemented;
         }

      //! @throws Not_Implemented
      template<typename verify_mode>
      void set_verify_mode(verify_mode v)
         {
         BOTAN_UNUSED(v);
         throw Not_Implemented("set_verify_mode is not implemented");
         }

      /**
       * Not Implemented.
       * @param ec Will be set to `Botan::ErrorType::NotImplemented`
       */
      template<typename verify_mode>
      void set_verify_mode(verify_mode v, boost::system::error_code& ec)
         {
         BOTAN_UNUSED(v);
         ec = Botan::ErrorType::NotImplemented;
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
      void handshake(Connection_Side side)
         {
         boost::system::error_code ec;
         handshake(side, ec);
         boost::asio::detail::throw_error(ec, "handshake");
         }

      /**
       * @brief Performs SSL handshaking.
       *
       * The function call will block until handshaking is complete or an error occurs.
       *
       * @param type The type of handshaking to be performed, i.e. as a client or as a server.
       * @param ec Set to indicate what error occurred, if any.
       */
      void handshake(Connection_Side side, boost::system::error_code& ec)
         {
         setup_native_handle(side, ec);

         if(side == CLIENT)
            {
            // send client hello, which was written to the send buffer on client instantiation
            send_pending_encrypted_data(ec);
            }

         while(!native_handle()->is_active() && !ec)
            {
            boost::asio::const_buffer read_buffer{input_buffer().data(), SocketWrapper<StreamLayer>(m_nextLayer, input_buffer(), ec)};
            if(ec)
               {
               return;
               }

            process_encrypted_data(read_buffer, ec);

            if(ec)
               {
               return;
               }
            }
         }

      /**
       * @brief Starts an asynchronous SSL handshake.
       *
       * This function call always returns immediately.
       *
       * @param type The type of handshaking to be performed, i.e. as a client or as a server.
       * @param handler The handler to be called when the handshake operation completes.
       *                The equivalent function signature of the handler must be: void(boost::system::error_code)
       */
      template <typename HandshakeHandler>
      auto async_handshake(Connection_Side side, HandshakeHandler&& handler) ->
      BOOST_ASIO_INITFN_RESULT_TYPE(HandshakeHandler, void(boost::system::error_code))
         {
         BOOST_ASIO_HANDSHAKE_HANDLER_CHECK(HandshakeHandler, handler) type_check;

         boost::system::error_code ec;
         setup_native_handle(side, ec);
         // If ec is set by setup_native_handle, the AsyncHandshakeOperation created below will do nothing but call the
         // handler with the error_code set appropriately - no need to early return here.


         if constexpr(!DTLS)
            {
            auto inception = std::make_shared<detail::AsyncHandshakeOperation<Stream>>(*this);

            auto interrupt = [this, handler, inception](const boost::system::error_code& errc) mutable
               {
               handler(errc);
               inception = nullptr;
               };

            inception->start(interrupt);
            }
         else
            {
            auto inception = std::make_shared<detail::AsyncHandshakeOperation<Stream>>(*this);

            auto interrupt = [this, handler, inception](const boost::system::error_code& errc) mutable
               {
               timeoutWatchDog_.cancel();
               repeatHandshake_.cancel();
               aborted_ = true;
               if(errc == boost::asio::error::operation_aborted)
                  {
                  handler(boost::asio::error::timed_out);
                  return;
                  }

               handler(errc);
               inception = nullptr;
               };
            inception->isDTLS = true;
            inception->start(interrupt);

            armRepeatHandshake(inception);
            armWatchdog();
            }
         }

      //! @throws Not_Implemented
      template<typename ConstBufferSequence, typename BufferedHandshakeHandler>
      BOOST_ASIO_INITFN_RESULT_TYPE(BufferedHandshakeHandler,
                                    void(boost::system::error_code, std::size_t))
      async_handshake(Connection_Side side, const ConstBufferSequence& buffers,
                      BufferedHandshakeHandler&& handler)
         {
         BOTAN_UNUSED(side, buffers, handler);
         BOOST_ASIO_HANDSHAKE_HANDLER_CHECK(BufferedHandshakeHandler, handler) type_check;
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
      void shutdown(boost::system::error_code& ec)
         {
         try_with_error_code([&]
            {
            native_handle()->close();
            }, ec);

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
      void shutdown()
         {
         boost::system::error_code ec;
         shutdown(ec);
         boost::asio::detail::throw_error(ec, "shutdown");
         }

   private:
      /**
       * @brief Internal wrapper type to adapt the expected signature of `async_shutdown` to the completion handler
       *        signature of `AsyncWriteOperation`.
       *
       * This is boilerplate to ignore the `size_t` parameter that is passed to the completion handler of
       * `AsyncWriteOperation`. Note that it needs to retain the wrapped handler's executor.
       */
      template <typename Handler, typename Executor>
      struct Wrapper
         {
         void operator()(boost::system::error_code ec, std::size_t)
            {
            handler(ec);
            }

         using executor_type = boost::asio::associated_executor_t<Handler, Executor>;

         executor_type get_executor() const noexcept
            {
            return boost::asio::get_associated_executor(handler, io_executor);
            }

         using allocator_type = boost::asio::associated_allocator_t<Handler>;

         allocator_type get_allocator() const noexcept
            {
            return boost::asio::get_associated_allocator(handler);
            }

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
       * @param handler The handler to be called when the shutdown operation completes.
       *                The equivalent function signature of the handler must be: void(boost::system::error_code)
       */
      template<typename ShutdownHandler>
      void async_shutdown(ShutdownHandler&& handler)
         {
         boost::system::error_code ec;
         try_with_error_code([&]
            {
            native_handle()->close();
            }, ec);
         // If ec is set by native_handle->close(), the AsyncWriteOperation created below will do nothing but call the
         // handler with the error_code set appropriately - no need to early return here.

         using ShutdownHandlerWrapper = Wrapper<ShutdownHandler, typename Stream::executor_type>;

         ShutdownHandlerWrapper w{std::forward<ShutdownHandler>(handler), get_executor()};
         BOOST_ASIO_SHUTDOWN_HANDLER_CHECK(ShutdownHandler, w) type_check;

         boost::asio::async_completion<ShutdownHandlerWrapper, void(boost::system::error_code, std::size_t)>
         init(w);

         detail::AsyncWriteOperation<typename std::decay<ShutdownHandlerWrapper>::type, Stream>
         op{std::move(init.completion_handler), *this, boost::asio::buffer_size(send_buffer())};

         return init.result.get();
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
      template<typename MutableBufferSequence>
      std::size_t read_some(const MutableBufferSequence& buffers,
                            boost::system::error_code& ec)
         {
         if(has_received_data())
            {
            return copy_received_data(buffers);
            }

         boost::asio::const_buffer read_buffer{input_buffer().data(), SocketWrapper<StreamLayer>::read(m_nextLayer, input_buffer(), ec)};
         if(ec)
            {
            return 0;
            }

         process_encrypted_data(read_buffer, ec);

         if(ec)  // something went wrong in process_encrypted_data()
            { return 0; }

         if(shutdown_received())
            {
            // we just received a 'close_notify' from the peer and don't expect any more data
            ec = boost::asio::error::eof;
            }
         else if(ec == boost::asio::error::eof)
            {
            // we did not expect this disconnection from the peer
            ec = StreamError::StreamTruncated;
            }

         return !ec ? copy_received_data(buffers) : 0;
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
      template<typename MutableBufferSequence>
      std::size_t read_some(const MutableBufferSequence& buffers)
         {
         boost::system::error_code ec;
         auto const n = read_some(buffers, ec);
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
      template<typename ConstBufferSequence>
      std::size_t write_some(const ConstBufferSequence& buffers,
                             boost::system::error_code& ec)
         {
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
      template<typename ConstBufferSequence>
      std::size_t write_some(const ConstBufferSequence& buffers)
         {
         boost::system::error_code ec;
         auto const n = write_some(buffers, ec);
         boost::asio::detail::throw_error(ec, "write_some");
         return n;
         }

      /**
       * @brief Start an asynchronous write. The function call always returns immediately.
       *
       * @param buffers The data to be written.
       * @param handler The handler to be called when the write operation completes. Copies will be made of the handler
       *        as required. The equivalent function signature of the handler must be:
       *        void(boost::system::error_code, std::size_t)
       */
      template <typename ConstBufferSequence, typename WriteHandler>
      auto async_write_some(const ConstBufferSequence& buffers, WriteHandler&& handler) ->
      BOOST_ASIO_INITFN_RESULT_TYPE(WriteHandler,
                                    void(boost::system::error_code, std::size_t))
         {
         BOOST_ASIO_WRITE_HANDLER_CHECK(WriteHandler, handler) type_check;

         boost::asio::async_completion<WriteHandler, void(boost::system::error_code, std::size_t)> init(handler);

         boost::system::error_code ec;
         tls_encrypt(buffers, ec);
         if(ec)
            {
            // we cannot be sure how many bytes were committed here so clear the send_buffer and let the
            // AsyncWriteOperation call the handler with the error_code set
            consume_send_buffer(m_send_buffer.size());
            detail::AsyncWriteOperation<typename std::decay<WriteHandler>::type, Stream>
            op{std::move(init.completion_handler), *this, std::size_t(0), ec};
            return init.result.get();
            }

         detail::AsyncWriteOperation<typename std::decay<WriteHandler>::type, Stream>
         op{std::move(init.completion_handler), *this, boost::asio::buffer_size(buffers)};

         return init.result.get();
         }

      /**
       * @brief Start an asynchronous read. The function call always returns immediately.
       *
       * @param buffers The buffers into which the data will be read. Although the buffers object may be copied as
       *                necessary, ownership of the underlying buffers is retained by the caller, which must guarantee
       *                that they remain valid until the handler is called.
       * @param handler The handler to be called when the read operation completes. The equivalent function signature of
       *                the handler must be:
       *                void(boost::system::error_code, std::size_t)
       */
      template <typename MutableBufferSequence, typename ReadHandler>
      auto async_read_some(const MutableBufferSequence& buffers, ReadHandler&& handler) ->
      BOOST_ASIO_INITFN_RESULT_TYPE(ReadHandler,
                                    void(boost::system::error_code, std::size_t))
         {
         BOOST_ASIO_READ_HANDLER_CHECK(ReadHandler, handler) type_check;

         boost::asio::async_completion<ReadHandler, void(boost::system::error_code, std::size_t)> init(handler);

         detail::AsyncReadOperation<typename std::decay<ReadHandler>::type, Stream, MutableBufferSequence>
         op{std::move(init.completion_handler), *this, buffers};
         return init.result.get();
         }

      //! @}

      //! @brief Indicates whether a close_notify alert has been received from the peer.
      bool shutdown_received() const
         {
         return m_shutdown_received;
         }

   protected:
      template<class H, class S, class M, class A> friend
      class detail::AsyncReadOperation;

      template<class H, class S, class A> friend
      class detail::AsyncWriteOperation;

      template<class S> friend
      class detail::AsyncHandshakeOperation;

      /**
       * @brief Helper class that implements Botan::TLS::Callbacks
       *
       * This class is provided to the stream's native_handle (Botan::TLS::Channel) and implements the callback
       * functions triggered by the native_handle.
       *
       * @param receive_buffer reference to the buffer where decrypted data should be placed
       * @param send_buffer reference to the buffer where encrypted data should be placed
       */
      class StreamCore : public Botan::TLS::Callbacks
         {
         public:
            StreamCore(Stream& stream) : m_stream(stream) {}

            virtual ~StreamCore() = default;

            void tls_emit_data(const uint8_t data[], std::size_t size) override
               {
               m_stream.m_send_buffer.commit(
                  boost::asio::buffer_copy(m_stream.m_send_buffer.prepare(size), boost::asio::buffer(data, size))
               );
               }

            void tls_record_received(uint64_t, const uint8_t data[], std::size_t size) override
               {
               if constexpr(DTLS)
                  {
                  isClientSending_ = true;
                  }

               m_stream.m_receive_buffer.commit(
                  boost::asio::buffer_copy(m_stream.m_receive_buffer.prepare(size), boost::asio::const_buffer(data, size))
               );
               }

            void tls_alert(Botan::TLS::Alert alert) override
               {
               if(alert.type() == Botan::TLS::Alert::CLOSE_NOTIFY)
                  {
                  m_stream.set_shutdown_received();
                  // Channel::process_alert will automatically write the corresponding close_notify response to the
                  // send_buffer and close the native_handle after this function returns.
                  }
               m_isAlerted = true;
               m_alert = alert;
               }

            std::chrono::milliseconds tls_verify_cert_chain_ocsp_timeout() const override
               {
               return std::chrono::milliseconds(1000);
               }

            bool tls_session_established(const Botan::TLS::Session& e) override
               {
               if(m_stream.m_context.m_tls_established_callback)
                  {
                    m_stream.m_context.m_tls_established_callback(e);
                  }
               return true;
               }

            void tls_verify_cert_chain(
               const std::vector<X509_Certificate>& cert_chain,
               const std::vector<std::shared_ptr<const OCSP::Response>>& ocsp_responses,
               const std::vector<Certificate_Store*>& trusted_roots,
               Usage_Type usage,
               const std::string& hostname,
               const TLS::Policy& policy) override
               {
               if(m_stream.m_context.has_verify_callback())
                  {
                  m_stream.m_context.get_verify_callback()(cert_chain, ocsp_responses, trusted_roots, usage, hostname, policy);
                  }
               else
                  {
                  Callbacks::tls_verify_cert_chain(cert_chain, ocsp_responses, trusted_roots, usage, hostname, policy);
                  }
               }


               bool isClientSending() const {
                 return isClientSending_;
               }

              // Lazy fix
              Botan::TLS::Alert m_alert{};
              bool m_isAlerted = false;
         private:
            Stream& m_stream;
            bool isClientSending_ = false;
         };

      const boost::asio::mutable_buffer& input_buffer()
         {
         return m_input_buffer;
         }

      boost::asio::const_buffer send_buffer() const
         {
         return m_send_buffer.data();
         }

      //! @brief Check if decrypted data is available in the receive buffer
      bool has_received_data() const
         {
         return m_receive_buffer.size() > 0;
         }

      //! @brief Copy decrypted data into the user-provided buffer
      template<typename MutableBufferSequence>
      std::size_t copy_received_data(MutableBufferSequence buffers)
         {
         // Note: It would be nice to avoid this buffer copy. This could be achieved by equipping the StreamCore with
         // the user's desired target buffer once a read is started, and reading directly into that buffer in tls_record
         // received. However, we need to deal with the case that the receive buffer provided by the caller is smaller
         // than the decrypted record, so this optimization might not be worth the additional complexity.
         const auto copiedBytes = boost::asio::buffer_copy(buffers, m_receive_buffer.data());
         m_receive_buffer.consume(copiedBytes);
         return copiedBytes;
         }

      //! @brief Check if encrypted data is available in the send buffer
      bool has_data_to_send() const
         {
         return m_send_buffer.size() > 0;
         }

      //! @brief Mark bytes in the send buffer as consumed, removing them from the buffer
      void consume_send_buffer(std::size_t bytesConsumed)
         {
         m_send_buffer.consume(bytesConsumed);
         }

      // This is a helper construct to allow mocking the native_handle in test code. It is activated by explicitly
      // specifying a (mocked) channel type template parameter when constructing the stream and does not attempt to
      // instantiate the native_handle.
      // Note: once we have C++17 we can achieve this much more elegantly using constexpr if.
      template<class T = ChannelT>
      typename std::enable_if<!std::is_same<Channel, T>::value>::type
      setup_native_handle(Connection_Side, boost::system::error_code&)
         {
         }

      /**
       * @brief Create the native handle.
       *
       * Depending on the desired connection side, this function will create a Botan::TLS::Client or a
       * Botan::TLS::Server.
       *
       * @param side The desired connection side (client or server)
       * @param ec Set to indicate what error occurred, if any.
       */
      template<class T = ChannelT>
      typename std::enable_if<std::is_same<Channel, T>::value>::type
      setup_native_handle(Connection_Side side, boost::system::error_code& ec)
         {
         Protocol_Version ver;
         if constexpr(DTLS)
            {
            ver = Protocol_Version::latest_dtls_version();
            }
         else
            {
            ver = Protocol_Version::latest_tls_version();
            }

         try_with_error_code([&]
            {
          if(side == CLIENT) {
            m_native_handle = std::unique_ptr<Client>(
                                 new Client(m_core,
                                            m_context.m_session_manager,
                                            m_context.m_credentials_manager,
                                            m_context.m_policy,
                                            m_context.m_rng,
                                            m_context.m_server_info,
                                            ver
                                           ));
            }
          else
            {
            isServer_ = true;
            m_native_handle = std::unique_ptr<Server>(
                                 new Server(m_core,
                                            m_context.m_session_manager,
                                            m_context.m_credentials_manager,
                                            m_context.m_policy,
                                            m_context.m_rng,
                                            ver.is_datagram_protocol()));
            }
            }, ec);
         }

      /** @brief Synchronously write encrypted data from the send buffer to the next layer.
       *
       * If this function is called with an error code other than 'Success', it will do nothing and return 0.
       *
       * @param ec Set to indicate what error occurred, if any. Specifically, StreamTruncated will be set if the peer
       *           has closed the connection but did not properly shut down the SSL connection.
       * @return The number of bytes written.
       */
      size_t send_pending_encrypted_data(boost::system::error_code& ec)
         {
         if(ec)
            {
            return 0;
            }

         size_t writtenBytes = SocketWrapper<StreamLayer>::write(m_nextLayer, send_buffer(), ec);
         consume_send_buffer(writtenBytes);

         if(ec == boost::asio::error::eof && !shutdown_received())
            {
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
      void tls_encrypt(const ConstBufferSequence& buffers, boost::system::error_code& ec)
         {
         // NOTE: This is not asynchronous: it encrypts the data synchronously.
         // The data encrypted by native_handle()->send() is synchronously stored in the send_buffer of m_core,
         // but is not actually written to the wire, yet.
         for(auto it = boost::asio::buffer_sequence_begin(buffers);
               !ec && it != boost::asio::buffer_sequence_end(buffers);
               it++)
            {
            const boost::asio::const_buffer buffer = *it;
            try_with_error_code([&]
               {
               native_handle()->send(static_cast<const uint8_t*>(buffer.data()), buffer.size());
               }, ec);
            }
         }

      /**
       * @brief Pass encrypted data to the native handle for processing.
       *
       * If an exception occurs while processing the data, an error code will be set.
       *
       * @param read_buffer Input buffer containing the encrypted data.
       * @param ec Set to indicate what error occurred, if any.
       */
      void process_encrypted_data(const boost::asio::const_buffer& read_buffer, boost::system::error_code& ec)
         {
         try_with_error_code([&]
            {
            native_handle()->received_data(static_cast<const uint8_t*>(read_buffer.data()), read_buffer.size());
            }, ec);
         }

      //! @brief Catch exceptions and set an error_code
      template <typename Fun>
      void try_with_error_code(Fun f, boost::system::error_code& ec)
         {
         try
            {
            f();
            }
         catch(const TLS_Exception& e)
            {
            ec = e.type();
            }
         catch(const Botan::Exception& e)
            {
            ec = e.error_type();
            }
         catch(const std::exception&)
            {
            ec = Botan::ErrorType::Unknown;
            }
         }

      void set_shutdown_received()
         {
         m_shutdown_received = true;
         }

      void armRepeatHandshake(const std::shared_ptr<detail::AsyncHandshakeOperation<Stream>>& aho)
         {
         repeatHandshake_.expires_from_now(boost::posix_time::milliseconds(50));
         repeatHandshake_.async_wait([this, aho](const boost::system::error_code& errc)
            {
            if(errc || aborted_)
               {
               return;
               }

            if(native_handle()->timeout_check())
               {
               boost::system::error_code ec;
               bool check = false;
               if(isServer_)
                  {
                  check = !m_core.isClientSending();
                  }
               else
                  {
                  check = !native_handle()->is_active();
                  }

               if(has_data_to_send() && check && !aho->writing_)
                  {
                  aho->writing_ = true;
                  SocketWrapper<SocketType>::async_write(next_layer(), send_buffer(),
                                                         [this, aho](const boost::system::error_code& errc, size_t bytes_transferred)
                     {
                     consume_send_buffer(bytes_transferred);
                     aho->writing_ = false;
                     if(aho->wantToWrite_)
                        {
                        aho->wantToWrite_ = false;
                        aho->operator()(errc, 0);
                        }
                     if(errc)
                        {
                        next_layer().close();
                        return;
                        }
                     armRepeatHandshake(aho);
                     });
                  return;
                  }
               }

            armRepeatHandshake(aho);
            });
         }

      void armWatchdog()
         {
         timeoutWatchDog_.expires_from_now(boost::posix_time::milliseconds(10000));
         timeoutWatchDog_.async_wait([this](const boost::system::error_code& errc)
            {
            if(errc || aborted_)
               {
               return;
               }
            watchDogTriggered_ = true;
            m_nextLayer.close();
            });
         }

      Context& m_context;
      StreamLayer m_nextLayer;

      boost::beast::flat_buffer m_receive_buffer;
      boost::beast::flat_buffer m_send_buffer;

      StreamCore m_core;
      std::unique_ptr<ChannelT> m_native_handle;

      bool m_shutdown_received;

      // Buffer space used to read input intended for the core
      std::vector<uint8_t> m_input_buffer_space;
      const boost::asio::mutable_buffer m_input_buffer;

      bool watchDogTriggered_ = false;
      bool aborted_ = false;
      bool isServer_ = false;
      boost::asio::deadline_timer repeatHandshake_{ get_executor() };
      boost::asio::deadline_timer timeoutWatchDog_{ get_executor() };
   };

}  // namespace TLS
}  // namespace Botan

#endif // BOOST_VERSION
#endif // BOTAN_ASIO_STREAM_H_
