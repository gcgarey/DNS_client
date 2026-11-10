import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Random;
import java.util.Scanner;
// 1. take user input of hostname from the command line,
// 2. create and issue a DNS query to a local DNS server
// 3. receive the corresponding response from said server
// 4. parse the response, 
// 5. display Question, Answer, Authority, Additional in command line

public class DNSClient{
    // helper method to help me debug
    public static String bytesToHex(byte[] bytes) {
    StringBuilder sb = new StringBuilder();
    for (byte b : bytes) {
        sb.append(String.format("%02X ", b));
        }
    return sb.toString().trim();
    }

    // Recursive function to handle byte names 
    public static String readName(byte[] buffer, int[] offset) {
        StringBuilder name = new StringBuilder();
        int current = offset[0];
        boolean jumped = false;

        while (true) {
            int len = buffer[current] & 0xFF;
            if (len == 0) {
                if (!jumped) offset[0] = current + 1;
                break;
            }
            if ((len & 0xC0) == 0xC0) { // compression pointer
                int ptr = ((len & 0x3F) << 8) | (buffer[current + 1] & 0xFF);
                if (!jumped) offset[0] = current + 2;
                current = ptr;
                jumped = true;
            } else {
                if (name.length() > 0) name.append(".");
                name.append(new String(buffer, current + 1, len));
                current += len + 1;
            }
        }
        return name.toString();
    }

    public static byte[] header() throws IOException{
        Random random = new Random();
        short ID = (short)random.nextInt(32767);
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        DataOutputStream dataOutputStream = new DataOutputStream(byteArrayOutputStream);

        // build the header (unecessarily long, but for my understanding)
        String flags = "0"; // QR
        flags += "0000"; //OpCode - 0 for standard query
        flags += "0"; // AA - Authorative answer
        flags += "0"; // TC truncation (yes/no)
        flags += "1"; // RD: recursion desired
        flags += "0"; // RA: is recursive support available in name server
        flags += "000"; // Zreserved - zero in all queries 
        flags += "0000"; // RDcode

        // parse string representation as a short in base 2, create a bytebuffer 
        // of short with length 2, transform bytebuffer into array of bytes
        short requestFlags = Short.parseShort(flags, 2);
        ByteBuffer flagsByteBuffer = ByteBuffer.allocate(2).putShort(requestFlags);
        byte[] flagsByteArray = flagsByteBuffer.array();

        short QDCount = 1; // number of entries in question
        // rest set by responding server
        short ANCount = 0; // number of resource records in answer section
        short NSCount = 0; // number of name server resource records in the authority records
        short ARCount = 0; // number of resource records in additonal records section 

        dataOutputStream.writeShort(ID);
        dataOutputStream.write(flagsByteArray);
        dataOutputStream.writeShort(QDCount);
        dataOutputStream.writeShort(ANCount);
        dataOutputStream.writeShort(NSCount);
        dataOutputStream.writeShort(ARCount);

        return byteArrayOutputStream.toByteArray();

    } 
    public static byte[] question(String domain) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        DataOutputStream dataOutputStream = new DataOutputStream(byteArrayOutputStream);

        String[] domainParts = domain.split("\\.");
        
        // Qname
        for (int i = 0; i < domainParts.length; i++){
            byte[] domainBytes = domainParts[i].getBytes(StandardCharsets.UTF_8);
            dataOutputStream.writeByte(domainBytes.length);
            dataOutputStream.write(domainBytes);
        }
        dataOutputStream.writeByte(0);

        dataOutputStream.writeShort(1); // Qtype, A = 1 (a host request)
        dataOutputStream.writeShort(1); // Qclass internet (IN) = 1

        return byteArrayOutputStream.toByteArray();
    }
    public static void parseResponse(byte[] response) throws IOException{
        // Read the header
        ByteBuffer buffer = ByteBuffer.wrap(response);
        int offset = 4;
        int QDCount = buffer.getShort(offset) & 0xFFFF; offset += 2;
        int ANCount = buffer.getShort(offset) & 0xFFFF; offset += 2;
        int NSCount = buffer.getShort(offset) & 0xFFFF; offset += 2;
        int ARCount = buffer.getShort(offset) & 0xFFFF; offset += 2;

        // Read question,
        System.out.println("QUESTION: ");
        for (int i = 0; i < QDCount; i++) {
            int[] tempOffset = {offset};
            String name = readName(response, tempOffset);
            offset = tempOffset[0];

            short qType = buffer.getShort(offset); offset += 2;
            short qClass = buffer.getShort(offset); offset += 2;

            String typeStr = (qType == 1) ? "A" : "type " + qType;
            String classStr = (qClass == 1) ? "IN" : "class " + qClass;
            System.out.println(name + "\t\t" + classStr + "\t" + typeStr);
        }

        // Read Answer
        System.out.println("ANSWER: ");
        for (int i = 0; i < ANCount; i++){
            int[] tempOffset = {offset};
            String name = readName(response, tempOffset);
            offset = tempOffset[0]; // offset was updated inside the method

            short type = buffer.getShort(offset); offset +=2;
            short cls = buffer.getShort(offset); offset +=2;
            int ttl = buffer.getInt(offset); offset += 4;
            short rdLen = buffer.getShort(offset); offset += 2;
            
            if (type == 1){ // A record
                // read 4 bytes and format like IP
                String ip = (response[offset] & 0xff) + "." + 
                            (response[offset + 1] & 0xff) + "." +
                            (response[offset + 2] & 0xff) + "." +
                            (response[offset + 3] & 0xff);
                System.out.println(name + "\t" + ttl + "\tIN\tA\t" + ip);
            }
            offset += rdLen;
        }

        // Read authority
        System.out.println("AUTHORITY: ");
        for (int i = 0; i < NSCount; i++){
            int[] tempOffset = {offset};
            String name = readName(response, tempOffset);
            offset = tempOffset[0]; // offset was updated inside the method

            short type = buffer.getShort(offset); offset +=2;
            short cls = buffer.getShort(offset); offset +=2;
            int ttl = buffer.getInt(offset); offset += 4;
            short rdLen = buffer.getShort(offset); offset += 2;
            
            if (type == 1){ // A record
                // read 4 bytes and format like IP
                String ip = (response[offset] & 0xff) + "." + 
                            (response[offset + 1] & 0xff) + "." +
                            (response[offset + 2] & 0xff) + "." +
                            (response[offset + 3] & 0xff);
                System.out.println("Authority: " + "\t" + name + "\t" + ttl + "\tIN\tA\t" + ip);
            }
            offset += rdLen;
        }

        // Read Additional
        System.out.println("ADDITIONAL: ");
        for (int i = 0; i < ARCount; i++){
            int[] tempOffset = {offset};
            String name = readName(response, tempOffset);
            offset = tempOffset[0]; // offset was updated inside the method

            short type = buffer.getShort(offset); offset +=2;
            short cls = buffer.getShort(offset); offset +=2;
            int ttl = buffer.getInt(offset); offset += 4;
            short rdLen = buffer.getShort(offset); offset += 2;
            
            if (type == 1){ // A record
                // read 4 bytes and format like IP
                String ip = (response[offset] & 0xff) + "." + 
                            (response[offset + 1] & 0xff) + "." +
                            (response[offset + 2] & 0xff) + "." +
                            (response[offset + 3] & 0xff);
                System.out.println("Additional: " + "\t" + name + "\t" + ttl + "\tIN\tA\t" + ip);
            }
            offset += rdLen;
        }

    }
    public static void main(String[] args) throws IOException{
        // Get user input for host name
        Scanner scanner = new Scanner(System.in);
        System.out.print("please enter a host name: ");
        String host = scanner.nextLine();
        scanner.close();

        // step 1: build the original query for DNS:
        byte[] header = header();
        byte[] question = question(host);
        ByteArrayOutputStream fullQuery = new ByteArrayOutputStream();
        fullQuery.write(header);
        fullQuery.write(question);
        byte[] dnsQuery = fullQuery.toByteArray();

        // Step 2: Send the query
        DatagramSocket socket = new DatagramSocket();
        InetAddress receiverAddress = InetAddress.getByName("8.8.8.8");
        int recieverPort = 53;
        DatagramPacket packet = new DatagramPacket(dnsQuery, dnsQuery.length,
             receiverAddress, recieverPort);
        socket.send(packet);

        // Step 3: recieve the response: 
        byte[] responseBuffer = new byte[512];
        DatagramPacket response = new DatagramPacket(responseBuffer, responseBuffer.length);
        socket.receive(response);
        byte[] bufResponse = response.getData(); 
        socket.close();
        
        // Step 4: Parse and print:
        parseResponse(bufResponse);

    }
} 