# **Exploring Alternatives**: Building Real-Time Chat Applications Without Javascript

## Pure HTML Real Time Chat Online With No Javascript

A truly **Simple Asynchronous** web chat that sends and receives messages in the browser with no reloads and no javascript, just pure **HTML** and **HTTP chunked encoding**. This project was inspired by [kkuchta css-only-chat project](https://github.com/kkuchta/css-only-chat).

## Preview

![image1](https://raw.githubusercontent.com/EDBCREPO/HTTPSocket/images/image1.gif)
![image2](https://raw.githubusercontent.com/EDBCREPO/HTTPSocket/images/image2.gif)

## Features

- It is complitly Asinchronous no pthread.
- The Server Knows when Client is connected.
- The Server Knows when Client is disconnected.
- The server suppots Poll, Epoll, WSAPoll, Kqueue.

## Dependencies

- **Openssl**
    - 🪟: `pacman -S mingw-w64-ucrt-x86_64-openssl`
    - 🐧: `sudo apt install libssl-dev`

- **Zlib**  
    - 🪟: `pacman -S mingw-w64-ucrt-x86_64-zlib`
    - 🐧: `sudo apt install zlib1g-dev`

- **Express:** [NodeppOficial/nodepp-express](https://github.com/NodeppOficial/nodepp-express)

- **Nodepp:** [NodeppOficial/nodepp](https://github.com/NodeppOficial/nodepp)

## How does it works

It is so simple, there are two things we need the browser to do. **Send Data** and **Receive Data**. Let's start with the first.

#### Sending Data

HTML is extrimly limited in what it can do. Hoever, we can use it to effectively send data to a server. in this case, I'm using a form with some basic inputs, that let me send messages to the server.

```html
<form action="/api/form" method="POST" enctype="text/plain">
    <input type="text" placeholder="message" required name="m" autocomplete="off" >
    <input type="submit" value="send">
</form>
```

The problem with the **Form Tag** is that it reloads the page every time a message is submitted, Worsening the user experience, to avoid this, I've decide to split the chat page in two parts using iframes, one is the message box, wich will be always loading for new messages, and other is the message form, wich is the form shown above, wich is reloaded every time a message is sent. 

```html
<!DOCTYPE html><html lang="en">

    <head>
        <meta charset="UTF-8"> <meta http-equiv="refresh" content="1">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Document</title>
    </head>

    <body>
        <iframe src="/api/msg" frameborder="0"></iframe>
        <iframe src="/api/form" frameborder="0"></iframe>
    </body>

</html>
```

With this improvement, the chat page will never reload on a message submit, improving the user experience.

#### Reading Data

Now is time to explain how read data. In this case we are going to use C++ along with [NodePP](https://github.com/NodeppOficial/nodepp) and [ExpressPP](https://github.com/NodeppOficial/nodepp-express) wich are libraries for C++ to make Asynchonous Applications and Web Applications with a NodeJS like sintax.

First, we need to create an express web server that let me server static files from **www** folder:

```cpp
#include <nodepp/nodepp.h>
#include <express/http.h>

using namespace nodepp;

void onMain() {

    auto app = express::http::add();

    app.USE( express::http::file("www") );

    app.listen( "0.0.0.0", 8000, []( ... ){
        console::log( "http://localhost:8000" );
    });

}
```

Second, we have to make a simple api to handle incomming and outcomming messages:

- **Incomming Message:**
```cpp
    app.ALL("/msg",[]( express_http_t cli ){
        
        // Enable HTTP chunk encoding 
        cli.header( "Transfer-Encoding", "chunked" );
        cli.header( "Content-Type", "text/html" );
        cli.send();

        // Disable Timeout Disonnection
        cli.set_timeout(0);

        // Print If Client is Connected
        console::log( "client connected" );

        // Initial HTML Mesage Box Payload
        string_t message = R"(<!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8"> <title>basepage</title>
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
            </head> <body>
            <div style="display:flex; flex-direction:column-reverse; gap:20px;">
        )"; 

        // Store this client into the client's list
        clients.push( cli ); 
        
        // Get the Client HTTP ID
        auto id = clients.last(); 

        // Write the payload
        cli.write( encoder::hex::get(message.size()) + "\r\n" + message + "\r\n" );
        
        // Print if client is disconnected from the message box
        cli.onDrain([=](){
            console::log( "client disconnected" );
            clients.erase( id );
        });

        // stream pipe to make it alive
        stream::pipe( cli );

    });
```

- **Outcomming Message:**
```cpp
    app.ALL("/form",[]( express_http_t cli ){

        // Detect if is a new message
        if( cli.headers["Content-Length"].empty() == false &&
            cli.headers["Content-Type"] == "text/plain" &&
            cli.method == "POST" 
        ){
            // check for length message
            auto len = string::to_ulong(cli.headers["Content-Length"]);
            // send the message 
            send_message_handler( clients, cli.read(len) );
            // reload the form page
            cli.redirect("/api/form"); return;
        }  
        
        // if is not POST method, send the form page
        cli.sendFile( path::join("www","form.html") );

    });
```
```cpp
    // this function is used to filter the messages to avoid css & js injection
    void send_message_handler( queue_t<express_http_t>& clients, string_t message ){
        // replace <> characters
        string_t flt  = regex::replace_all( message.slice(2), "[><]+", "" );
        // format the message using html tags
        string_t msg  = regex::format( "<div>${0}</div>", flt );
        // encode the message using chunk encoding
        string_t data = encoder::hex::get( msg.size() ) + "\r\n" + msg + "\r\n";
        // send the message to every client connected
        auto n = clients.first(); while( n != nullptr ) { n->data.write( data ); n=n->next; }
    }
```

## The Final Result

![image3](https://raw.githubusercontent.com/EDBCREPO/HTTPSocket/images/image3.png)
