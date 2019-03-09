#########################################################################
# name: execarver                                                       #
# author: Mankirat Gulati                                               #
# version: 1.0                                                          #
# description: A file extractor that carves PE files from TCP traffic.  #                                              #
#########################################################################

----------------------------------------------
Setup Instructions:
----------------------------------------------
1. Give executable permissions to 'setup.sh'.

    chmod u+x setup.sh

2. Run 'setup.sh'.

    source setup.sh


----------------------------------------------
Running the program:
----------------------------------------------
1. Running the below command will give you insight on all the 
   informtion and features about the program.

    python3 execarver.py --help

    *** Example: The following command that listens on interface 'eth0', 
            with a BPF filter of 'TCP'.

        python3 execarver.py -i eth0 TCP

2. I have implemented some additional features that may be useful.
   
    *** The '--strict' flag:
        
        Some PE files either do not have the PE signature or
        they are not at the correct offset, 0x3c.

        If this flag is included, execarver will only carve out PE files
        that have the PE signature at the correct offset.

    *** The '--exact' flag:     

        If this flag is included, execarver will attempt to carve
        out the exact number of bytes the file should be by looking
        at the Content-Length of the HTTP header.

        Otherwise, the file size will be relatively arbitrary.

3. Core Implementation Details

    *** Carved .exe files have the following naming convention: 
        
        file-0.exe, file-1.exe, file-2.exe, etc... 

        where the numbers correspond to the sequence of EXE files found.


----------------------------------------------
Example Test Run:
----------------------------------------------
1. Run 'python3 execarver.py'
2. Run 'wget http://www.winimage.com/download/winima90.exe' in a
   second terminal.
3. Once the file has finished downloading, go to the first terminal
   and terminate the program (CTRL + C).
4. The following output is:

    Terminal #1:
    ---------------
        root@kali:~/Documents/cse363/hw1# python3 execarver.py 
        Listening on default interface, 'eth0'...
        ^C
        Extracted file, 'file-0.exe' with a size of 764474 bytes.

    Terminal #2
    ---------------
        root@kali:~/Documents/cse363/hw1# wget http://www.winimage.com/download/winima90.exe
        --2019-02-22 17:37:08--  http://www.winimage.com/download/winima90.exe
        Resolving www.winimage.com (www.winimage.com)... 142.44.145.26
        Connecting to www.winimage.com (www.winimage.com)|142.44.145.26|:80... connected.
        HTTP request sent, awaiting response... 200 OK
        Length: 746592 (729K) [application/x-msdownload]
        Saving to: ‘winima90.exe.2’

        winima90.exe.2      100%[===================>] 729.09K  1.48MB/s    in 0.5s    

        2019-02-22 17:37:09 (1.48 MB/s) - ‘winima90.exe.2’ saved [746592/746592]

