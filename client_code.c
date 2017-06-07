#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>			//inet_pton(): convert IPv4 and IPv6 addresses from text to binary form
#include <netdb.h>
#include <string.h>

#define SERVER_PORT 2016
#define BUF_SIZE 4096


void fatal(char* );

//Important Note: From lines 16 to 162 there are copied lines from sha1.cpp as gcc does not allow multiple file compilations at the same time, I had to choose this way to import sha1 methods.

// Rotate an integer value to left.
        inline const unsigned int rol(const unsigned int value,
                const unsigned int steps)
        {
            return ((value << steps) | (value >> (32 - steps)));
        }

        // Sets the first 16 integers in the buffert to zero.
        // Used for clearing the W buffert.
        inline void clearWBuffert(unsigned int* buffert)
        {
		int pos;
            for (pos = 16; --pos >= 0;)
            {
                buffert[pos] = 0;
            }
        }

        void innerHash(unsigned int* result, unsigned int* w)
        {
            unsigned int a = result[0];
            unsigned int b = result[1];
            unsigned int c = result[2];
            unsigned int d = result[3];
            unsigned int e = result[4];

            int round = 0;

            #define sha1macro(func,val) \
			{ \
                const unsigned int t = rol(a, 5) + (func) + e + val + w[round]; \
				e = d; \
				d = c; \
				c = rol(b, 30); \
				b = a; \
				a = t; \
			}

            while (round < 16)
            {
                sha1macro((b & c) | (~b & d), 0x5a827999)
                ++round;
            }
            while (round < 20)
            {
                w[round] = rol((w[round - 3] ^ w[round - 8] ^ w[round - 14] ^ w[round - 16]), 1);
                sha1macro((b & c) | (~b & d), 0x5a827999)
                ++round;
            }
            while (round < 40)
            {
                w[round] = rol((w[round - 3] ^ w[round - 8] ^ w[round - 14] ^ w[round - 16]), 1);
                sha1macro(b ^ c ^ d, 0x6ed9eba1)
                ++round;
            }
            while (round < 60)
            {
                w[round] = rol((w[round - 3] ^ w[round - 8] ^ w[round - 14] ^ w[round - 16]), 1);
                sha1macro((b & c) | (b & d) | (c & d), 0x8f1bbcdc)
                ++round;
            }
            while (round < 80)
            {
                w[round] = rol((w[round - 3] ^ w[round - 8] ^ w[round - 14] ^ w[round - 16]), 1);
                sha1macro(b ^ c ^ d, 0xca62c1d6)
                ++round;
            }

            #undef sha1macro

            result[0] += a;
            result[1] += b;
            result[2] += c;
            result[3] += d;
            result[4] += e;
        }
    

    void calc(const void* src, const int bytelength, unsigned char* hash)
    {
        // Init the result array.
        unsigned int result[5] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 };

        // Cast the void src pointer to be the byte array we can work with.
        const unsigned char* sarray = (const unsigned char*) src;

        // The reusable round buffer
        unsigned int w[80];

        // Loop through all complete 64byte blocks.
        const int endOfFullBlocks = bytelength - 64;
        int endCurrentBlock;
        int currentBlock = 0;

        while (currentBlock <= endOfFullBlocks)
        {
            endCurrentBlock = currentBlock + 64;
	int roundPos;
            // Init the round buffer with the 64 byte block data.
            for (roundPos = 0; currentBlock < endCurrentBlock; currentBlock += 4)
            {
                // This line will swap endian on big endian and keep endian on little endian.
                w[roundPos++] = (unsigned int) sarray[currentBlock + 3]
                        | (((unsigned int) sarray[currentBlock + 2]) << 8)
                        | (((unsigned int) sarray[currentBlock + 1]) << 16)
                        | (((unsigned int) sarray[currentBlock]) << 24);
            }
            innerHash(result, w);
        }

        // Handle the last and not full 64 byte block if existing.
        endCurrentBlock = bytelength - currentBlock;
        clearWBuffert(w);
        int lastBlockBytes = 0;
        for (;lastBlockBytes < endCurrentBlock; ++lastBlockBytes)
        {
            w[lastBlockBytes >> 2] |= (unsigned int) sarray[lastBlockBytes + currentBlock] << ((3 - (lastBlockBytes & 3)) << 3);
        }
        w[lastBlockBytes >> 2] |= 0x80 << ((3 - (lastBlockBytes & 3)) << 3);
        if (endCurrentBlock >= 56)
        {
            innerHash(result, w);
            clearWBuffert(w);
        }
        w[15] = bytelength << 3;
        innerHash(result, w);
	int hashByte;
        // Store hash in result pointer, and make sure we get in in the correct order on both endian models.
        for (hashByte = 20; --hashByte >= 0;)
        {
            hash[hashByte] = (result[hashByte >> 2] >> (((3 - hashByte) & 0x3) << 3)) & 0xff;
        }
    }

void toHexString(const unsigned char* hash, char* hexstring)
    {
        const char hexDigits[] = { "0123456789abcdef" };
	int hashByte;
        for (hashByte = 20; --hashByte >= 0;)
        {
            hexstring[hashByte << 1] = hexDigits[(hash[hashByte] >> 4) & 0xf];
            hexstring[(hashByte << 1) + 1] = hexDigits[hash[hashByte] & 0xf];
        }
        hexstring[40] = 0;
    }
	

int main(int argc, char ** argv)
{
	int c,sD,bytes;
	char buffer[BUF_SIZE];
	struct sockaddr_in dest;
	char message[BUF_SIZE];

	char greet[17] = "Start_Connection";
	char *toHash;	//string to hash
	char hexKey[33] = "6b94e2d66a7439a3c0805a5c9c489acf";
	char randomHex[33];
	char number[11] = "#150130205";
	char *toHex = (char *) malloc(20);	//hash buffer to be converted to hex string
	char sha1result[41];			//hashed string in hex string form
	char * myPass = (char *) malloc(50);	//hashed string + number
	
	

	
	sD = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);	//open socket
	if(sD < 0 ) 			fatal("Unable to open socket");
		
	memset(&dest, 0, sizeof(dest));
	dest.sin_family = AF_INET;
	inet_pton(AF_INET, "160.75.26.117", &dest.sin_addr);		//use given server ip adress
	dest.sin_port = htons(SERVER_PORT);
	 
	c = connect(sD, (struct sockaddr *) &dest, sizeof(dest)); //create connection to the socket
	if(c < 0 )			fatal("connection failed");
	printf("Connection established\n");

	write(sD, greet, strlen(greet));
	bytes  = read(sD, buffer, BUF_SIZE);	//read randomhex to the buffer
	strcpy(randomHex, buffer);			//copy randomHex from buffer
	toHash = strcat(randomHex,hexKey);		//add randomHex and hexKey together
	calc(toHash,64,	toHex);			//send random+hexKey to hash function
	toHexString(toHex,sha1result);		//convert hash buffer to hex string
	myPass = strcat(sha1result,number);	//create pass to be used by adding number to the hex string
	write(sD, myPass, 50);			//send pass to the server
	printf("\nPass Sent\n"); 	
	bytes = read(sD, buffer, BUF_SIZE);	//read from server(Proceed?)
	write(1, buffer, bytes);
	printf("\nEnter message: \n");
	scanf("%s",message);			
	write(sD, message, strlen(message));	//Enter y and continue
			
	int counter =0; // question counter
	while(1){
		if(counter >= 6) break;		//break if quiz is over

		if(counter > 0){		//read twice and send answer(for question 2-6)
			bytes = read(sD, buffer, BUF_SIZE);	//read server response to the previous answer	
			write(1, buffer, bytes);		// print response to cmd
			bytes = read(sD, buffer, BUF_SIZE);	// read next question text
			write(1, buffer, bytes);	
			printf("\nEnter message: \n");		
			scanf("%s",message);			//get user input
			if (strcmp(message,"close") == 0) break; //break if input is close	
			write(sD, message, 1);			//send answer to the server
		}
		
		else{			//read once and send answer(for first question)
			bytes = read(sD, buffer, BUF_SIZE);	//read first question from server	
			write(1, buffer, bytes);		//print to the screen
			printf("\nEnter message: \n");
			scanf("%s",message);			//get user input
			if (strcmp(message,"close") == 0) break;	
			write(sD, message, 1);			//write answer to the server
			
		}
		counter++;
	}
	
	close(sD); // close socket
	
	free (toHex); // free pre-allocated memory to avoid memory leaks
	free (myPass); // free pre-allocated memory to avoid memory leaks
	
	return 0;
}


void fatal(char* message)
{
	printf("%s \n", message);
	exit(1);

}

