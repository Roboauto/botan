/*
* Helpers for TLS ASIO Stream
* (C) 2018-2020 Jack Lloyd
*     2018-2020 Hannes Rantzsch, Tim Oesterreich, Rene Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ASIO_ASYNC_OPS_H_
#define BOTAN_ASIO_ASYNC_OPS_H_

#include <botan/build.h>
#include <boost/version.hpp>

#if BOOST_VERSION >= 106600

#include <botan/asio_error.h>

// We need to define BOOST_ASIO_DISABLE_SERIAL_PORT before any asio imports. Otherwise asio will include <termios.h>,
// which interferes with Botan's amalgamation by defining macros like 'B0' and 'FF1'.
#define BOOST_ASIO_DISABLE_SERIAL_PORT

#include <boost/asio.hpp>
#include <boost/asio/yield.hpp>
#include <botan/asio_op_wrappers.h>

namespace Botan {
namespace TLS {
namespace detail {

/**
 * Base class for asynchronous stream operations.
 *
 * Asynchronous operations, used for example to implement an interface for boost::asio::async_read_some and
 * boost::asio::async_write_some, are based on boost::asio::coroutines.
 * Derived operations should implement a call operator and invoke it with the correct parameters upon construction. The
 * call operator needs to make sure that the user-provided handler is not called directly. Typically, yield / reenter is
 * used for this in the following fashion:
 *
 * ```
 * void operator()(boost::system::error_code ec, std::size_t bytes_transferred, bool isContinuation = true)
 *    {
 *    reenter(this)
 *       {
 *       // operation specific logic, repeatedly interacting with the stream_core and the next_layer (socket)
 *
 *       // make sure intermediate initiating function is called
 *       if(!isContinuation)
 *          {
 *          yield next_layer.async_operation(empty_buffer, this);
 *          }
 *
 *       // call the completion handler
 *       complete_now(error_code, bytes_transferred);
 *       }
 *    }
 * ```
 *
 * Once the operation is completed and ready to call the completion handler it checks if an intermediate initiating
 * function has been called using the `isContinuation` parameter. If not, it will call an asynchronous operation, such
 * as `async_read_some`, with and empty buffer, set the object itself as the handler, and `yield`. As a result, the call
 * operator will be invoked again, this time as a continuation, and will jump to the location where it yielded before
 * using `reenter`. It is now safe to call the handler function via `complete_now`.
 *
 * \tparam Handler Type of the completion handler
 * \tparam Executor1 Type of the asio executor (usually derived from the lower layer)
 * \tparam Allocator Type of the allocator to be used
 */
template<class Handler, class Executor1, class Allocator>
class AsyncBase : public boost::asio::coroutine
   {
   public:
      using allocator_type = boost::asio::associated_allocator_t<Handler, Allocator>;
      using executor_type = boost::asio::associated_executor_t<Handler, Executor1>;

      allocator_type get_allocator() const noexcept
         {
         return boost::asio::get_associated_allocator(m_handler);
         }

      executor_type get_executor() const noexcept
         {
         return boost::asio::get_associated_executor(m_handler, m_work_guard_1.get_executor());
         }

   protected:
      template<class HandlerT>
      AsyncBase(HandlerT&& handler, const Executor1& executor)
         : m_handler(std::forward<HandlerT>(handler)), m_work_guard_1(executor)
         {
         }

      /**
       * Call the completion handler.
       *
       * This function should only be called after an intermediate initiating function has been called.
       *
       * @param args Arguments forwarded to the completion handler function.
       */
      template<class... Args>
      void complete_now(Args&& ... args)
         {
         m_work_guard_1.reset();
         m_handler(std::forward<Args>(args)...);
         }

      Handler m_handler;
      boost::asio::executor_work_guard<Executor1> m_work_guard_1;
   };

template<class Handler, class Stream, class MutableBufferSequence, class Allocator = std::allocator<void>>
class AsyncReadOperation : public AsyncBase<Handler, typename Stream::executor_type, Allocator>
   {
   public:
      /**
       * Construct and invoke an AsyncReadOperation.
       *
       * @param handler Handler function to be called upon completion.
       * @param stream The stream from which the data will be read
       * @param buffers The buffers into which the data will be read.
       * @param ec Optional error code; used to report an error to the handler function.
       */
      template<class HandlerT>
      AsyncReadOperation(HandlerT&& handler,
                         Stream& stream,
                         const MutableBufferSequence& buffers,
                         const boost::system::error_code& ec = {})
         : AsyncBase<Handler, typename Stream::executor_type, Allocator>(
              std::forward<HandlerT>(handler),
              stream.get_executor()), m_stream(stream), m_buffers(buffers), m_decodedBytes(0)
         {
         this->operator()(ec, std::size_t(0), false);
         }

      AsyncReadOperation(AsyncReadOperation&&) = default;

      void operator()(boost::system::error_code ec, std::size_t bytes_transferred, bool isContinuation = true)
         {
         reenter(this)
            {
            if(bytes_transferred > 0 && !ec)
               {
               // We have received encrypted data from the network, now hand it to TLS::Channel for decryption.
               boost::asio::const_buffer read_buffer{m_stream.input_buffer().data(), bytes_transferred};
               m_stream.process_encrypted_data(read_buffer, ec);
               }

            if (m_stream.shutdown_received())
               {
               // we just received a 'close_notify' from the peer and don't expect any more data
               ec = boost::asio::error::eof;
               }
            else if (ec == boost::asio::error::eof)
               {
               // we did not expect this disconnection from the peer
               ec = StreamError::StreamTruncated;
               }

            if(!m_stream.has_received_data() && !ec && boost::asio::buffer_size(m_buffers) > 0)
               {
               // The channel did not decrypt a complete record yet, we need more data from the socket.
               SocketWrapper<typename Stream::SocketType>::async_read(m_stream.next_layer(), m_stream.input_buffer(),
                     std::move(*this));
               return;
               }

            if(m_stream.has_received_data() && !ec)
               {
               // The channel has decrypted a TLS record, now copy it to the output buffers.
               m_decodedBytes = m_stream.copy_received_data(m_buffers);
               }

            else if(!isContinuation)
               {
               // Make sure the handler is not called without an intermediate initiating function.
               // "Reading" into a zero-byte buffer will complete immediately.
               m_ec = ec;
               yield
               SocketWrapper<typename Stream::SocketType>::async_read(m_stream.next_layer(), boost::asio::mutable_buffer(),
                     std::move(*this));
               ec = m_ec;
               }

            this->complete_now(ec, m_decodedBytes);
            }
         }

   private:
      Stream& m_stream;
      MutableBufferSequence m_buffers;
      std::size_t m_decodedBytes;
      boost::system::error_code m_ec;
   };

template<typename Handler, class Stream, class Allocator = std::allocator<void>>
class AsyncWriteOperation : public AsyncBase<Handler, typename Stream::executor_type, Allocator>
   {
   public:
      /**
       * Construct and invoke an AsyncWriteOperation.
       *
       * @param handler Handler function to be called upon completion.
       * @param stream The stream from which the data will be read
       * @param plainBytesTransferred Number of bytes to be reported to the user-provided handler function as
       *                              bytes_transferred. This needs to be provided since the amount of plaintext data
       *                              consumed from the input buffer can differ from the amount of encrypted data written
       *                              to the next layer.
       * @param ec Optional error code; used to report an error to the handler function.
       */
      template<class HandlerT>
      AsyncWriteOperation(HandlerT&& handler,
                          Stream& stream,
                          std::size_t plainBytesTransferred,
                          const boost::system::error_code& ec = {})
         : AsyncBase<Handler, typename Stream::executor_type, Allocator>(
              std::forward<HandlerT>(handler),
              stream.get_executor()), m_stream(stream), m_plainBytesTransferred(plainBytesTransferred)
         {
         this->operator()(ec, std::size_t(0), false);
         }

      AsyncWriteOperation(AsyncWriteOperation&&) = default;

      void operator()(boost::system::error_code ec, std::size_t bytes_transferred, bool isContinuation = true)
         {
         reenter(this)
            {
            // mark the number of encrypted bytes sent to the network as "consumed"
            // Note: bytes_transferred will be zero on first call
            m_stream.consume_send_buffer(bytes_transferred);

            if(m_stream.has_data_to_send() && !ec)
               {
               SocketWrapper<typename Stream::SocketType>::async_write(m_stream.next_layer(), m_stream.send_buffer(),
                     std::move(*this));
               return;
               }

            if (ec == boost::asio::error::eof && !m_stream.shutdown_received())
               {
               // transport layer was closed by peer without receiving 'close_notify'
               ec = StreamError::StreamTruncated;
               }

            if(!isContinuation)
               {
               // Make sure the handler is not called without an intermediate initiating function.
               // "Writing" to a zero-byte buffer will complete immediately.
               m_ec = ec;
               yield
               SocketWrapper<typename Stream::SocketType>::async_write(m_stream.next_layer(), boost::asio::const_buffer(),
                     std::move(*this));
               ec = m_ec;
               }

            // The size of the sent TLS record can differ from the size of the payload due to TLS encryption. We need to
            // tell the handler how many bytes of the original data we already processed.
            this->complete_now(ec, m_plainBytesTransferred);
            }
         }

   private:
      Stream& m_stream;
      std::size_t m_plainBytesTransferred;
      boost::system::error_code m_ec;
   };

template<class Stream
         >
class AsyncHandshakeOperation
   {
   private:
      static inline boost::asio::thread_pool handshakeThreadPool_{ std::thread::hardware_concurrency() ? std::thread::hardware_concurrency() : 16 };
   public:
      /**
       * Construct and invoke an AsyncHandshakeOperation.
       *
       * @param handler Handler function to be called upon completion.
       * @param stream The stream from which the data will be read
       * @param ec Optional error code; used to report an error to the handler function.
       */

      AsyncHandshakeOperation(
         Stream& stream,
         const boost::system::error_code& ec = {})
         : m_stream(stream)
         {

         }

      AsyncHandshakeOperation(AsyncHandshakeOperation&& other) = default;

      template<class HandlerT>
      void start(HandlerT&& handler)
         {
         m_handler = handler;
         this->operator()({}, std::size_t(0), false);
         }

      void write()
         {
         if(writing_)
            {
            wantToWrite_ = true;
            return;
            }
         writing_ = true;
         SocketWrapper<typename Stream::SocketType>::async_write(
            m_stream.next_layer(), m_stream.send_buffer(),
            [this](const boost::system::error_code& errc, size_t transferred)
            {
            if(errorState_)
               {
               m_stream.native_handle()->close();
               }
            writing_ = false;
            m_stream.consume_send_buffer(transferred);
            this->operator()(errc, 0);
            });
         }

      void operator()(boost::system::error_code ec, std::size_t bytesTransferred, bool isContinuation = true)
         {
         if(bytesTransferred > 0)
            {
            // Provide encrypted TLS data received from the network to TLS::Channel for decryption
            auto work = std::make_shared<boost::asio::executor_work_guard<typename Stream::executor_type>>(m_stream.get_executor());
            boost::asio::post(handshakeThreadPool_, [this, bytesTransferred, work, ec] () mutable
               {
               std::function<void()> result;
               try
                  {
                    if(ec == boost::asio::error::eof)
                    {
                      m_ec = StreamError::StreamTruncated;
                    }

                    if(bytesTransferred > 0 && !ec)
                    {
                      // Provide encrypted TLS data received from the network to TLS::Channel for decryption
                      boost::asio::const_buffer read_buffer {m_stream.input_buffer().data(), bytesTransferred};
                      m_stream.process_encrypted_data(read_buffer, m_ec);
                    }
                  result = [this]()
                     {
                     if(m_stream.m_core.m_isAlerted)
                        {
                        if(m_stream.m_core.m_alert.is_fatal())
                           {
                           m_has_exception_cat = true;
                           boost::system::error_code ecTmp = boost::system::error_code(m_stream.m_core.m_alert.type(), botan_alert_category());
                           m_last_cat = BotanExceptionCategory(ecTmp.message());
                           errorState_ = true;
                           write();
                           return;
                           }
                        else
                           {
                           m_stream.native_handle()->send_alert(m_stream.m_core.m_alert);
                           m_stream.m_core.m_isAlerted = false;
                           }
                        };
                     this->operator()(m_ec, 0); // Continue
                     };
                  }
               catch(const TLS_Exception& e)
                  {
                  result = [this, e]()
                     {
                     m_has_exception_cat = true;
                     m_last_cat = BotanExceptionCategory(e.what());
                     errorState_ = true;
                     write();
                     };
                  }
               catch(const Botan::Exception& e)
                  {
                  result = [this, e]()
                     {
                     m_has_exception_cat = true;
                     m_last_cat = BotanExceptionCategory(e.what());
                     errorState_ = true;
                     write();
                     };
                  }
               catch(...)
                  {
                  result = [this]()
                     {
                     m_has_exception_cat = true;
                     m_last_cat = BotanExceptionCategory("Unknown exception");
                     errorState_ = true;
                     write();
                     };
                  }
               boost::asio::post(m_stream.get_executor(), result); // Post the post process back to io_context
               });

            return;
            }

         if(m_stream.has_data_to_send() && !ec)
            {
            // Write encrypted TLS data provided by the TLS::Channel on the wire

            // Note: we construct `AsyncWriteOperation` with 0 as its last parameter (`plainBytesTransferred`). This
            // operation will eventually call `*this` as its own handler, passing the 0 back to this call operator.
            // This is necessary because the check of `bytesTransferred > 0` assumes that `bytesTransferred` bytes
            // were just read and are available in input_buffer for further processing.
            write();
            return;
            }

         if(isDTLS && m_stream.isServer_)
            {
            if(!m_stream.m_core.isClientSending() && !ec && !m_has_exception_cat)
               {
               // Read more encrypted TLS data from the network
               SocketWrapper<typename Stream::SocketType>::async_read(m_stream.next_layer(), m_stream.input_buffer(),
                     [this](const boost::system::error_code& errc, size_t transferred)
                  {
                  this->operator()(errc, transferred);
                  });
               return;
               }
            }
         else
            {
            if(!m_stream.native_handle()->is_active() && !ec && !m_has_exception_cat)
               {
               // Read more encrypted TLS data from the network
               SocketWrapper<typename Stream::SocketType>::async_read(m_stream.next_layer(), m_stream.input_buffer(),
                     [this](const boost::system::error_code& errc, size_t transferred)
                  {
                  this->operator()(errc, transferred);
                  });
               return;
               }
            }

         if(!isContinuation)
            {
            // Make sure the handler is not called without an intermediate initiating function.
            // "Reading" into a zero-byte buffer will complete immediately.
            m_ec = ec;


            SocketWrapper<typename Stream::SocketType>::async_read(m_stream.next_layer(), boost::asio::mutable_buffer(),
                  [this](const boost::system::error_code& errc, size_t transferred)
               {
               this->operator()(errc, transferred);
               });
            ec = m_ec;
            }

         if(m_has_exception_cat)
            {
            boost::system::error_code errc(1, m_last_cat);
            m_handler(errc);
            m_stream.next_layer().close();
            }
         else
            {
            m_handler(ec);
            }

         }

      bool writing_ = false;
      bool wantToWrite_ = false;
      bool isDTLS = false;
   private:
      bool errorState_ = false;
      std::function<void(const boost::system::error_code&)> m_handler;
      Stream& m_stream;
      BotanExceptionCategory m_last_cat{""};
      bool m_has_exception_cat = false;
      boost::system::error_code m_ec;
   };

}  // namespace detail
}  // namespace TLS
}  // namespace Botan

#include <boost/asio/unyield.hpp>

#endif // BOOST_VERSION
#endif // BOTAN_ASIO_ASYNC_OPS_H_
