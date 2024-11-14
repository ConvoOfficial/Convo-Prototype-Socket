#include <nodepp/nodepp.h>
#include <nodepp/encoder.h>
#include <express/http.h>

using namespace nodepp;

queue_t<express_http_t> clients;

void send_message_handler( queue_t<express_http_t>& clients, string_t message ){
    string_t flt  = regex::replace_all( message.slice(2), "[><]+", "" );
    string_t msg  = regex::format( "<div>${0}</div>", flt );
    string_t data = encoder::hex::get( msg.size() ) + "\r\n" + msg + "\r\n";
    auto n = clients.first(); while( n != nullptr ) { n->data.write( data ); n=n->next; }
}

express_tcp_t apiRestFull_Handler() {

    auto app = express::http::add();

    app.ALL("/form",[]( express_http_t cli ){

        if( cli.headers["Content-Length"].empty() == false &&
            cli.headers["Content-Type"] == "text/plain" &&
            cli.method == "POST" 
        ){
            auto len = string::to_ulong(cli.headers["Content-Length"]);
            send_message_handler( clients, cli.read(len) );
            cli.redirect("/api/form"); return;
        }  
        
        cli.sendFile( path::join("www","form.html") );
    });

    app.ALL("/msg",[]( express_http_t cli ){
        
        cli.header( "Transfer-Encoding", "chunked" );
        cli.header( "Content-Type", "text/html" );
        cli.send(); clients.push( cli ); 
        cli.set_timeout(0);

        console::log( "client connected" );

        string_t message = R"(<!DOCTYPE html>
            <html lang="en"> <head>
                <meta charset="UTF-8"> <title>basepage</title>
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
            </head> <body> <div style="display:flex; flex-direction:column-reverse; gap:20px;">
        )"; auto id = clients.last(); 

        cli.write( encoder::hex::get(message.size()) + "\r\n" + message + "\r\n" );
        
        cli.onDrain([=](){
            console::log( "client disconnected" );
            clients.erase( id );
        });

        stream::pipe( cli );

    });

    return app;

}

void onMain() {

    auto app = express::http::add();

    app.USE( "/api", apiRestFull_Handler() );

    app.USE( express::http::file("www") );

    app.listen( "0.0.0.0", 8000, []( ... ){
        console::log( "-> http://localhost:8000" );
    });

}