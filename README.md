================================================================================
HTTPieces Server        -  CONTRIBUTORS NEEDED  -

Game-changing developer-centric HTTPS server for development or production.

HTTPieces is intended to be an easy to deploy and use, fast, powerful web server 
designed to simplify collaboration between front-end developers on web projects.


It allows for multiple front-end developers to work on different parts of the same
front-end project simultaneously while mitigating the main draw-backs of having
developers work on the same "branch" of a project at the same time.  Some of the
benefits are:

    * Developers work on parts of the project that only they have permissions
      to modify keeping the scope of their responsibility squarely in their 
      court and preventing overwriting of each others' files.

    * Bugs / console logging in one developer's code can be prevented from 
      affecting others working on the same project by excluding or designating
      only the parts of the project to serve via query string directive.

    * Viewing the progress of the entire project is simple and seamless by
      loading the project by it's URL without any special query string 
      directives.

    * Allows for breaking down of the source code to more specific / specialized 
      files for super easy code maintenance.  E.g. The "index" file can be split
      so that multiple developers can work on different aspects of even the 
      main landing page using "include" directives.  

      From the perspective of the browser, there will be no additional HTTP
      requests; the project will be assembled and served in its entirety.  

      Example:

      URL: https://example.com/index.html

      <!DOCTYPE html>
      <html>
            <head>
                <style>
                    /** include: bob/css/navagation.css **/
                    /** include: alice/css/main/report.css **/
                </style>
            </head>
            <body>
                <!-- include: bob/html/main/navigation.html -->
                <!-- include: alice/html/main/report.html -->
                <script>
                    /** include: bob/script/main/navigation_events.js **/
                    /** include: alice/script/main/report.js **/
                </script>
            </body>
      </html>

      If Alice wanted to view and test her report without loading Bob's 
      JavaScript, she could use the URL: 

      https://example.com/index.html?no-load=bob/script/main/navigation_events.js

      If she wanted to exclude ALL of Bob's code, she could use:

      https://example.com/index.html?no-load=bob



The server will keep project files cached and indexed to quickly build
responses.  Additionally and configurably, it will keep responses 
cached and gzipped - invalidating and rebuilding cache as files are modified.


HTTPieces will have command-line functionality to compile an HTTPieces project
into a compressed file ready to unzip and deploy in canonical fashion on any
standard production HTTP server - Although HTTPieces, per se, will be a very
fast and efficient production server.


************************************************
*            HTTPieces Features:               *
************************************************


    * HTTP/2, HTTP/1.1

    * WebSocket (either Upgraded HTTP/1.1, or over HTTP/2) pass-through via
      HTTPieces Delegates.


    * TLS v1.2 and 1.3

    * Resource caching and Compression

    * Extensible CGI with simple configuration capable of natively and 
      easily using any scripting language or program installed on the server
      capable of obtaining its input via "stdin" and sending its output to
      "stdout" or "stderr".

    * HTTPieces Delegates.  A delegate is a program or script that can be
      registered in "httpieces.conf" for which HTTPieces acts as a smart proxy.
      HTTPieces will connect to the delegate via either Unix or Internet domain
      socket passing data it has received from the internet to the delegate, and
      serving the delegate's output to the internet-side client.

      This is especially useful because the delegate simply has to be able to
      read and write from a clear-text stream.  It doesn't have to deal with
      the intricacies of decoding the internet-side protocol via which the 
      client is connected.

      Use Cases:

        1. WebSocket

            A website wants to establish a bi-directional WebSocket connection
            with a server.  HTTPieces will handle the connection, TLS, and
            encoding / decoding of WebSocket (and HTTP/2 if applicable) frames.

            The delegate will simply have to worry about parsing and responding
            to the request.
      
            
        2. Infrastructure Compatibility

            A company has a legacy servlet application incapable of handling 
            more up-to-date protocols (possibly higher TLS versions or HTTP/2)
            that it needs to continue serving resources.  

            It can be registered as a delegate that accepts HTTP.  HTTPieces 
            will forward HTTP/1.1 messages to it after handling the TLS; it
            will also decode and assemble HTTP/2 messages, passing them to the
            servlet in standard HTTP format.

            * DEV NOTE *
            HTTPieces should also be able to "spoof"..."translate"...(call it 
            what you want) HTTP versions in case the delegate can't handle
            "HTTP/2" in the request line.
            
        3. Custom services.

            HTTPieces can proxy any of the following connection types for a
            delegate:

                a. Raw TCP
                b. Raw TCP over TLS
                c. Raw UDP
                d. DTLS (UDP over TLS)
                e. HTTP (including aforementioned note...HTTP version translation)
                f. WebSocket




More info coming soon.








