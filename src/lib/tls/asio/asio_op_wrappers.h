#pragma once

#include <stdint.h>
#include <boost/asio.hpp>

template <typename SocketType>
struct SocketWrapper
   {
   template<typename ...Args>
   static std::size_t read(SocketType&, Args&& ...)
      {
      static_assert(true, "Read operation not specialized for this socket type");
      }

   template<typename ...Args>
   static std::size_t write(SocketType&, Args&& ...)
      {
      static_assert(true, "Write operation not specialized for this socket type");
      }

   template<typename ...Args>
   static void async_receive_from(SocketType& socket, Args&& ... args)
      {
      static_assert(true, "Receive_from operation not specialized for this socket type");
      }

   };

template <>
struct SocketWrapper<boost::asio::ip::udp::socket>
   {
   template<typename MutableBufferSequence, typename X = boost::system::error_code>
   static std::size_t read(boost::asio::ip::udp::socket& socket, MutableBufferSequence&& buffer, X&& errc)
      {
      return socket.receive(buffer, 0, errc);
      }

   template<typename ...Args>
   static std::size_t read(boost::asio::ip::udp::socket& socket, Args&& ... args)
      {
      return socket.receive(std::forward<Args>(args)...);
      }

   template<typename ...Args>
   static void async_receive_from(boost::asio::ip::udp::socket& socket, Args&& ... args)
      {
      return socket.async_receive_from(std::forward<Args>(args)...);
      }

   template<typename MutableBufferSequence, typename X = boost::system::error_code>
   static std::size_t write(boost::asio::ip::udp::socket& socket, MutableBufferSequence&& buffer, X&& errc)
      {
      return socket.send(buffer, 0, errc);
      }

   template<typename ...Args>
   static std::size_t write(boost::asio::ip::udp::socket& socket, Args&& ... args)
      {
      return socket.send(std::forward<Args>(args)...);
      }

   template<typename ...Args>
   static void async_read(boost::asio::ip::udp::socket& socket, Args&& ... args)
      {
      socket.async_receive(std::forward<Args>(args)...);
      }

   template<typename ...Args>
   static void async_write(boost::asio::ip::udp::socket& socket, Args&& ... args)
      {
      socket.async_send(std::forward<Args>(args)...);
      }
   };

template <>
struct SocketWrapper<boost::asio::ip::tcp::socket >
   {
   template<typename ...Args>
   static std::size_t read(boost::asio::ip::tcp::socket& socket, Args&& ... args)
      {
      return socket.read_some(std::forward<Args>(args)...);
      }

   template<typename ...Args>
   static std::size_t write(boost::asio::ip::tcp::socket& socket, Args&& ... args)
      {
      return boost::asio::write(socket, std::forward<Args>(args)...);
      }

   template<typename ...Args>
   static void async_read(boost::asio::ip::tcp::socket& socket, Args&& ... args)
      {
      socket.async_read_some(std::forward<Args>(args)...);
      }

   template<typename ...Args>
   static void async_write(boost::asio::ip::tcp::socket& socket, Args&& ... args)
      {
      socket.async_write_some(std::forward<Args>(args)...);
      }
   };
