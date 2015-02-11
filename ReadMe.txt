== TinySSL - A Very Small, Simple to Use and Extremely Fast SSL Library in C ==
    COPYRIGHT © 2014 ANTHONY MAI (MAI_ANTHONY@HOTMAIL.COM). ALL RIGHTS RESERVED.

================    INTRODUCTION    ============================

    This is the TinySSL open source SSL library package written by Anthony Mai.
The author distribute this package as open source software to promote its usage.
There are many other open source cryptographic libraries available for the SSL
(Secure Socket Layer) and TLS (transport layer security). But I feel that people
want a package that contains just the mimimal features required to work, is very
simple and easy to use, and runs fast. This package is created for that purpose.
An original copy of this open source package, named TinySSL, can be obtained from
SourceForge under the URL:	http://sourceforge.net/projects/tinyssl/

================    COPYRIGHT AND DISTRIBUTION    ==============

    This open source package was written by Anthony Mai (Mai_Anthony@hotmail.com)
who retains full copyrights of this work but choose to distribute the software in
open source form. As such, this and the other copyright notices contained in this
package are NOT to be modified or removed. If this package is used in a product,
the author Anthony Mai should be given attribution as the author of the parts of
the library used. This can be in the form of a textual message at program startup
or in documentation (online or textual) provided with the product package. This
package was originally hosted at the SourceForge open source repository under URL:

        http://sourceforge.net/projects/tinyssl/

    Distribution may also be available at other internet sites. The author RETAINS
full copyrights for all distributions, altered or un-altered. Any usage, modification
and re-distribution of this software package must comply with all the requirements
specified within this software package, and with all the copyright notices remaining
intact and distributed in their entirety together with the rest of the package.

    PLEASE NOTE: ABSOLUTELY NO PARTIAL DISTRIBUTION OF THIS PACKAGE IS ALLOWED.

    If this software is compiled and embedded into a commercial or non-commercial
product, and the original source code package cannot be reasonably delivered with
the product, this and other copyright notice containsed within this software package
must NOT be removed, and must be provided in information and documentations, with
the original source and author of this software package fully acknowledged, and
the end users are provided the information and opportunity to freely obtain a full
and intact original copy of this software package, and/or to contact the original
author. You have fulfilled the NO-PARTIAL DISTRIBUTION requirement by showing that
full distribution of this package with your product is unreasonable and difficult,
and that you have fully acknowledged the source of this software, and provided to
the end user information and opportunity to freely obtain a full copy on their own.

    This library is distributed freely for commercial and non-commercial use under
the following conditions. The following conditions apply to all code found in this
distribution, and their derivative products:

    1. Redistributions of source code must retain the copyright notices, this list
       of conditions and the following disclaimers, in their entireties. Distribution
       of source code, modified or not, must be made freely available to the general
       public without restrictions except for as specified in this or other copyright
       notices. The sole purpose of the restrictions provided are meant to ensure:
            a. This package and its derivative works shall remain freely available.
            b. The author shall retain full copyrights and be properly acknowledged.
            c. The author shall never be held liable for any liability or warranty.

    2. Redistributions in binary form must reproduce the above copyright notice,
       this list of conditions and the following disclaimer in the documentation
       and/or other materials provided with the distribution.

    3. All advertising materials mentioning features or use of this software must
       display the following acknowledgement:

       This product contains software written by Anthony Mai (Mai_Anthony@hotmail.com)
       The original source code can be obtained from SourceForge.net or the other open
       source internet sites, or by contacting the author directly.

    4. This software may or may not contain patented technology owned by a third party.
       Obtaining a copy of this software, with or without explicit authorization from
       the author, does NOT imply that applicable patents have been licensed. It is up
       to users of this package ascertain that utilization of this software package
       does not result in infringement or other violation of any third party's patents,
       copyrights, trade marks or other intellectual proerty rights.

    PLEASE NOTE: ABSOLUTELY NO IMPLIED OR EXPLICITLY EXPRESSED WARRANTY IS PROVIDED

THIS SOFTWARE IS PROVIDED BY ANTHONY MAI "AS IS". ANY EXPRESS OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 
The licence and distribution terms for any publically available version or derivative
of this code cannot be changed.  i.e. this code cannot simply be copied and put under
another distribution licence [including the GNU Public Licence.]

================    Getting Started    =========================

    This TinySSL software package is a C language library that provides very basic
cryptographic features and enables secure data communication through computer networks
using SSL (Secure Socket Layer) and TLS (Transport Layer Security). The goal of this
package is not to provide a full featured complete package, but to provide an easy to
use, compact size and efficient solution to application developers so they can enable
secure data communication quickly without all the learning curves and the un-necessary
baggages in developing their own software products. This package can also be used as
education material. By making the source code freely available, the author hopes to
promote its usage and promote development of simple to understand, logically elegant,
easy to use and highly robust and efficient software products. Please be aware that
open source software is just a form of distributin. It does not does equal to free
software or software code without copyright. If you are confused, please read the
clarification near the end of this ReadMe document.

    Source files contained in the package provides four functional blocks:

    1) An implementation of the RSA public key cryptograpy.

    2) Implementation of commonly cipher and hash algorithms: RC4, MD5, SHA-1 & SHA-256.

    3) Implementation of basic features of the widely used X.509 digital certificates.

    4) Implementation of the SSL2.0, SSL3.0, SSL3.1 and TLS1.0 internet protocol.

    The source files are arranged under two separate subdirectories, src and include.
The *.h header files under the include subdirectory should provide a sufficient API
for application developers to use, without digging into the implementation details.
If you are developing server side application, you may need to acces headers and
source files under teh src subdirectory. The package provides only the minimum and
basic features so it will fully work, but without the dangling bells and whistles.

    The source files does not contain any network code. It is up to developers to
implement the actual network connection. Once connected, the package helps to handle
the communication protocol and encrypt/decrypt the data. You are free to use anynetwork
solution, and plug in additional or replacement symmetric ciphers or hash modules.
So the package is pretty flexible. It is written in very portable generic C code.
So it sould be very easy to port it to any platform, big endian or little endian,
32 bits or 63 or 128 bits. It should also be easy to be ported to embedded systems.

    The source files and header files contained are listed below:

Under http://sourceforge.net/projects/tinyssl/

    ReadMe.txt      - This read me document you are reading.

    /include        - The include file folder, containing API header files
        BN.h        - API for Big Number arithmatics for RSA implementation
        cert.h      - API for X.509 digital certificate authentication.
        cipher.h    - API for a generic way of accessing ciphers and hashes.
        md5.h       - API for the MD5 message hash algorithm.
        rc4.h-      - API for the popular RC4 symmetric cipher.
        sha1.h      - API for the SHA-1 message hash algirithm.
        sha256.h    - API for the SHA-256 message hash algorith,
        ssl.h       - API for SSL/TLS network protocol client implementation. 

    /src            - The source file folder, containing C implementation files

        BN.c        - Big Number algorithm for RSA key generation, encryption/decryption
        cert.c      - X.509 digital certificate parsing and authentication.
        certSamples.h   - Header for declaration of sample RSA keys and certificates.
        certSamples.c   - Binary data array of the sample RSA keys and certificates.
        cipher.c    - A generic wrapper for symmetric ciphers and hash algorithms.
        clientMsg.h - Header for the client side SSL/TLS message handling.
        clientMsg.c - Source file of client side SSL/TLS message handling.
        endian.h    - Header for accesory functions to handle endianness conversion.
        endian.c    - Source file of the functions to handle endianness conversion.
        hmac.h      - Header for MAC, Message Authentication Code, functions.
        hmac.c      - Source file of MAC algorithms used in SSL/TLS protocols.
        main.c      - A main test program demonstrating usage of this library.
        md5.c       - Source file for the MD5 hash algorithm implementation.
        msecret.h   - Header file for the Master Secret processing in SSL/TLS
        msecret.c   - Course file for the Master Secret processing in SSL/TLS
        rc4.c       - Source file for the RC4 symmetric cipher implementation.
        serverMsg.h - Header for the server side SSL/TLS message handling.
        serverMsg.c - Source file of server side SSL/TLS message handling.
        sha1.c      - Source file for SHA-1 hash algorithm implementation.
        sha256.c    - Source file for SHA-256 hash algorithm implementation.
        ssl.c       - Main SSL/TLS protocl client impmenetation library file.
        sslServer.h - API header file for server side SSL/TLS implementation.
        sslServer.c - Source file for main server side SSL/TLS implementation.
        sslTest.h   - Header file to access the SSL/TLS test of both client and server.
        sslTest.c   - Test code for running a client/server SSL/TLS session together.
        ssl_int.h   - Internal header files for SSL/TLS implementation.

    That's all. Altogether the package contains 17 headers and 17 source files.
Except for main.c and ssl_int.h who does not have their peers, the other 16 are
paired C header and source files. I hope the API header files are simple enough
that they explain themselves well.

    No make files or project files are included. These are not necessary. A good
software source package should explain themselves and be self contained, and should
not rely on external project settings to function normally. Depending on the specifc
platform and development tool you are porting this library to, you can easily set up
your own project files to compile and build the package.

    The sample.c contains several pieces of RSA keys and certificates. Certificates
and RSA public keys are public information with no security risk when distributed.
RSA private keys are critical security information that can not be disclosed when
the key is in practical and commercial usage. The sample.c contains a Google web
site certificate issued by Google, a Google certificate authority certificate issued
by GeoTrust, and GeoTrust root certificate. These are publicly available information
easily obtained by any one. So there should not be a problem including them for tests.

    The sample.c also include a Anthony Mai Certificate Authority root certificate
I created on my own. A server RSA public and private key pair and a server certificate
issued by myself. These are for test purpose only and should NOT be used in finished
products. I created them on the fly and for testing purpose only. This is NOT my real
root certificate, although I can safely say that no one else possesses my root keys.

    The software package, written in generic C, should be very easily portable to
many embedded or non-embedded platforms, although I have only tested on Win32. I
have optimized assembly code implemnetations for some of the performance critical
subroutines, and can help you to fine tune the code for best performance on your
platform. But the package, already very efficient as it is, is meant to be an easy
to use and portable package, not a package of the state of the art performance.

    If you have any question, go visit the SourceForge web site and participate in
the discussion. If you contact me directly, I may not answer promptly but I will
try my best to help you any way I can, with your specific implementation question.


================    A Few Words About Open Source Software =====

    This TinySSL software package is distributed as an Open Source software. But
the author retains full copyrights. Some people may be confused. A lot of people
thought that open source software means free software, and it means there is no
copyright, and that anybody can do anything with the software package unrestricted.

    That popularly held myth is completely wrong. Open source software is just a
form of distribution. It does not equal to free software. And free software does not
mean it has no copyrights. And copyrighted software does not mean it cannot be made
freely available. On the other hand, non-copyrighted material can be sold for money
or its re-distribution can be restricted. There are several related but different
legal concepts independent from each other here.

What is Intellectual Property

    Intellectual property is information, knowhow, ideas and expression created by
productive mental creations that have been expressed, recorded and or shared. They
are not tangible physical items, but have value in their retainment, distribution
and usage. Anything that has value is a private property protected by the relevant
private property laws until and unless it is expressly abandoned by the property
holder, or that the protection has expired and or becomes ineffective. When a piece
of intellectual property is expressly abandoned, it becomes public domain as no one
can claim ownership any more, and any body can do anything about it as they wish.

    Computer softwares are created by mental creations. They are the intellectual
properties of the original creators or other entities that inherited the ownership.
Softwares are protected in different ways at different levels.

What is Public Domain

    When the owner of a software work expressly disclaims any title of rights or
ownership, it becomes abaondoned property and enters the public domain. No one can
claim any ownership to a software in public domain. Likewise, no one can hold any
one liable for the usage and distribution of public domain software, as it is for
every member of the public to share and use, and every one has equal claim to it.
Most open source software packages are NOT public domain software, unless it was
expressedly stated by the original owner that it was abandoned and put into the
public domain. Once placed in public domain, no one can take possession any more
as the package will remain in public domain indefinitely. Public domain software
has no intellectual protection and no warranty or liability whatsoever. All other
software works entertain some form of protection, and may or may not have some
warranties or liability associated with them.

    The TinySSL software package is NOT a public domain software package.

Warranty and Liability

    When some entity releases a product to the public, it oftens comes with a promise
that the product shall perform in a certain way and or provide certain benefits while
avoiding certain harms. Such promise, provided by the producer and entended to the end
user, encourages and promotes the distribution and usage of the product, which is in
the interest of the producer. Warranties and liabilities are expressedly given by the
producer. If no such primise is made, or the producer explicitly disclaim any such
promise, then there is no warranty or liability provided, and the end user must not
hold the producer liable for anything. Put it simple, use at your own risk. If you do
not want to take the risk, you have the option of simply do not acquire and use it.

    Author of the TinySSL software package expressly disclaims any and all warranty.

Copyrighted Materials

    Original creator or owner of an intellectual property has the right to control the
way how the property can be shared, distributed or used. The owner's right to control
the sharing, copying and or distribution of their products, is the copyright.

    An intellectual work with its copyright expressly disclaimed by the owner, is a
non-copyrighted work, or copyleft material. It means the owner abandons all controls
and restrictions regarding the sharing and distribution of their works. It does NOT
mean that the owner has abandoned all rights and claims to their work. You may freely
distribute it, download it and upload it in any way you want, give it to any one, or
even take it apart and give parts to some one. No restriction on sharing whatsoever.
But the owner still retains other property rights. The ownership can be retained.
You cannot wipe out the author's name and replace it with your own name. You cannot
distribute it without giving the author proper acknowlegdment of credit. You may not
have the right to use it in certain ways until you get the permission from the owner.
Or you may have to obtain permission to use a patented method or idea. Remember, just
because you have possession of something in your hand, doesn't necessary mean you have
the right to use it. Obtaining something, and obtaining rights to use it, is different.

    Some author does not like the idea of totally abandoning the right to control the
distribution of their software work, even among the folks who want to see their work
to be distributed as widely as possible, and does not seek to gain money or fame from
it. The reason is some one may turn around to possess the distribution right and then
impose restrictions. So retaining some control of the distribution can ensure that the
package can remain freely distributed as much as possble.

    The author of TinySSL retains FULL copyrights of this work. That means both the
distribution and usage of this package must adhere to the conditions set forth by
the author, and remains so until further notice of otherwise.

What is Free Software

    When people say free software, they often thought it means free as free lunch,
meaning no money is required and the author will never want to get money from it,
and the author is giving it to the public as Santa Clause. However there really is
no free lunch, and Santa Clause rarely shows up. Computer software developers need
to make a living, too. They are not Santa Clauses for sure.

    Free software more likely means software that is freely distributed, meaning
free as in freedom of speech, not as free in free beer. Developing computer software
is hard work. Developers want as many people as possible to use their software and
like them. They want their products to see as wide a distribution as possible. Asking
for money for the dsitribution restricts the scope of distributions, as well as
imposing other restrictive requirements. It does not mean that the developer cannot
gain in other ways other than directly asking for money. For example a programmer
can gain reputable and credibility, or can be paid by a commercial developer out of
gratitudes or desire for co-operation.

    Open source means the source code of the software, instead of the compiled binary
program, is distributed. Open source does not mean it is free software. Free software
does not mean it is open source. There are free softwares that totally non-open source,
for example viruses. You are not asked for money when a computer virus infects your
computer, and virus authors want their destruction as widely distrubuted as possible.
For developers of useful software products, making the source code available helps to
leverage the intelligence of the public to improve it, and helps the product to gain
acceptace and popularity.

    Open source does not mean it's free software. Open source is not necesarily free
in the sense of free lunch, or even in the sense of freedom of distribution. Free
stuff may not be freely distributed: You can take a copy from a stack of free news
papers, but it is absolutely not allowed that you remove the whole stack. A restaurant
or a charity may offer free lunch, but you can not take food away after you have eaten.

    Likewise, books does not need to be sold in open source form: Why do they allow
people visiting a bookstore to be able to pick up a book and read it, and even spend
a whole day in the book store reading through the whole book, or that people can go to
a library and borrow the book to read, without paying a penny? Why not sell the books
in a closed blackbox, or in some sort of encrypted media container, and to make sure
that people do not get to read a single character until they have paid. Obviously
very few book will be sold if you go that way. Books are more often sold as open
source: You have the opportunity to see the entire thing before you pay. Just as
open shelf booksotes are popular, open source software is also becoming more popular.

    The TinySSL software package is an open source and free software. You can use it
for free in commercial and non-commercial products. But it is not in public domain.
The author retains all copyrights and deserves full credit for making it available.

================    End of This ReadMe.txt Document ============
