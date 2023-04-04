package ca.ubc.cs.cs317.dnslookup;

import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.util.*;

public class DNSLookupService {

    public static final int DEFAULT_DNS_PORT = 53;
    private static final int MAX_INDIRECTION_LEVEL_NS = 10;
    private static final int MAX_QUERY_ATTEMPTS = 3;
    private static final int MAX_DNS_MESSAGE_LENGTH = 512;
    private static final int SO_TIMEOUT = 5000;

    private final DNSCache cache = DNSCache.getInstance();
    private final Random random = new Random();
    private final DNSVerbosePrinter verbose;
    private final DatagramSocket socket;

    /**
     * Creates a new lookup service. Also initializes the datagram socket object with a default timeout.
     *
     * @param verbose    A DNSVerbosePrinter listener object with methods to be called at key events in the query
     *                   processing.
     * @throws SocketException      If a DatagramSocket cannot be created.
     * @throws UnknownHostException If the nameserver is not a valid server.
     */
    public DNSLookupService(DNSVerbosePrinter verbose) throws SocketException, UnknownHostException {
        this.verbose = verbose;
        socket = new DatagramSocket();
        socket.setSoTimeout(SO_TIMEOUT);
    }

    /**
     * Closes the lookup service and related sockets and resources.
     */
    public void close() {
        socket.close();
    }

    /**
     * Examines a set of resource records to see if any of them are an answer to the given question.
     *
     * @param rrs       The set of resource records to be examined
     * @param question  The DNS question
     * @return          true if the collection of resource records contains an answer to the given question.
     */
    private boolean containsAnswer(Collection<ResourceRecord> rrs, DNSQuestion question) {
        for (ResourceRecord rr : rrs) {
            if (rr.getQuestion().equals(question) && rr.getRecordType() == question.getRecordType()) {
                return true;
            }
        }
        return false;
    }

    /**
     * Finds all the results for a specific question. If there are valid (not expired) results in the cache, uses these
     * results, otherwise queries the nameserver for new records. If there are CNAME records associated to the question,
     * they are retrieved recursively for new records of the same type, and the returning set will contain both the
     * CNAME record and the resulting resource records of the indicated type.
     *
     * @param question             Host and record type to be used for search.
     * @param maxIndirectionLevels Number of CNAME indirection levels to support.
     * @return A set of resource records corresponding to the specific query requested.
     * @throws DNSErrorException If the number CNAME redirection levels exceeds the value set in
     *                           maxIndirectionLevels.
     */
    public Collection<ResourceRecord> getResultsFollowingCNames(DNSQuestion question, int maxIndirectionLevels)
            throws DNSErrorException {

        if (maxIndirectionLevels < 0) throw new DNSErrorException("CNAME indirection limit exceeded");

        Collection<ResourceRecord> directResults = iterativeQuery(question);
        if (containsAnswer(directResults, question)) {
            return directResults;
        }

        Set<ResourceRecord> newResults = new HashSet<>();
        for (ResourceRecord record : directResults) {
            newResults.add(record);
            if (record.getRecordType() == RecordType.CNAME) {
                newResults.addAll(getResultsFollowingCNames(
                        new DNSQuestion(record.getTextResult(), question.getRecordType(), question.getRecordClass()),
                        maxIndirectionLevels - 1));
            }
        }
        return newResults;
    }

    /**
     * Answers one question.  If there are valid (not expired) results in the cache, returns these results.
     * Otherwise it chooses the best nameserver to query, retrieves results from that server
     * (using individualQueryProcess which adds all the results to the cache) and repeats until either:
     *   the cache contains an answer to the query, or
     *   the cache contains an answer to the query that is a CNAME record rather than the requested type, or
     *   every "best" nameserver in the cache has already been tried.
     *
     *  @param question Host name and record type/class to be used for the query.
     */
    public Collection<ResourceRecord> iterativeQuery(DNSQuestion question)
            throws DNSErrorException {
        Set<ResourceRecord> ans = new HashSet<>();
        /* TODO: To be implemented by the student */

        List<ResourceRecord> list;

        if (!cache.getCachedResults(question).isEmpty()) {
            // If there are valid results in the cache, return the results
            return cache.getCachedResults(question);

        } else {

            // Create a list of the best name servers for the question
            list = cache.getBestNameservers(question);
            // Create a list of A resource records for the subset of the provided nameservers
            List<ResourceRecord> ipAd = cache.filterByKnownIPAddress(list);

            if (ipAd.size() == 0) {
                // If the list of name servers do not have an IP associated, query for those name servers
                // Call iterativeQuery with the question being the additional information hostname
                // Fills up the cache

                for (int i = 0; i < list.size(); i++) {
                    DNSQuestion q = new DNSQuestion(list.get(0).getTextResult(), RecordType.A, list.get(0).getRecordClass());
                    ipAd.addAll(iterativeQuery(q));
                }
            }

            for (int i = 0; i < ipAd.size(); i++) {

                ResourceRecord rr = ipAd.get(i);
                InetAddress inet = rr.getInetResult();
                Set<ResourceRecord> set = individualQueryProcess(question, inet);

                if (set == null) {
                    // Null Query (Ignore)
                } else {
                    // Fills up the cache
                    ans.addAll(individualQueryProcess(question, inet));
                }
            }
            ans.clear();
            // Recall the method to continue find the best name servers, or find the answer within the cache.
            return iterativeQuery(question);
        }


    }

    /**
     * Handles the process of sending an individual DNS query with a single question. Builds and sends the query (request)
     * message, then receives and parses the response. Received responses that do not match the requested transaction ID
     * are ignored. If no response is received after SO_TIMEOUT milliseconds, the request is sent again, with the same
     * transaction ID. The query should be sent at most MAX_QUERY_ATTEMPTS times, after which the function should return
     * without changing any values. If a response is received, all of its records are added to the cache.
     * <p>
     * If the reply contains a non-zero Rcode value, then throw a DNSErrorException.
     * <p>
     * The method verbose.printQueryToSend() must be called every time a new query message is about to be sent.
     *
     * @param question Host name and record type/class to be used for the query.
     * @param server   Address of the server to be used for the query.
     * @return If no response is received, returns null. Otherwise, returns a set of all resource records
     * received in the response.
     * @throws DNSErrorException if the Rcode in the response is non-zero
     */
    public Set<ResourceRecord> individualQueryProcess(DNSQuestion question, InetAddress server)
            throws DNSErrorException {
        /* TODO: To be implemented by the student */

        try {

            // Builds the DNSMessage query and initialize all variables
            DNSMessage query = buildQuery(question);
            byte[] buf = query.getUsed();
            int length = buf.length;
            int ID = query.getID();

            // Calling printQueryToSend before sending the query
            verbose.printQueryToSend(question, server, ID);
            // Initializing the DatagramPacket
            DatagramPacket out = new DatagramPacket(buf, length, server, DEFAULT_DNS_PORT);
            socket.send(out);

            // Creating the response buffer and allowing incoming information to be written on the buffer
            ByteBuffer rBuf = ByteBuffer.allocate(MAX_DNS_MESSAGE_LENGTH);
            DatagramPacket in = new DatagramPacket(rBuf.array(), rBuf.limit());

            int numQ = 0;
            for (numQ = 0; numQ < MAX_QUERY_ATTEMPTS; numQ++) {

                try {
                    // Receive the information
                    socket.receive(in);

                    // Create the DNSMessage to check for ID and QR
                    byte[] response = rBuf.array();
                    DNSMessage message = new DNSMessage(response, response.length);

                    if (message.getID() != ID || message.getQR() != true) {
                        // If ID does not match or QR is not true, then ignore and resend
                        verbose.printQueryToSend(question, server, ID);
                        socket.send(out);
                    } else {
                        // Else return the processed response of the incoming message
                        return processResponse(message);
                    }

                } catch (SocketTimeoutException e) {
                    // If timeout is reached, resend the query
                    verbose.printQueryToSend(question, server, ID);
                    socket.send(out);

                }

            }

            if (numQ == MAX_QUERY_ATTEMPTS) {
                // If max query attempts is reached, return null
                return null;
            }


        } catch (IOException e) {

            return null;

        }

        return null;
    }

    /**
     * Creates a DNSMessage containing a DNS query.
     * A random transaction ID must be generated and filled in the corresponding part of the query. The query
     * must be built as an iterative (non-recursive) request for a regular query with a single question. When the
     * function returns, the message's buffer's position (`message.buffer.position`) must be equivalent
     * to the size of the query data.
     *
     * @param question    Host name and record type/class to be used for the query.
     * @return The DNSMessage containing the query.
     */
    public DNSMessage buildQuery(DNSQuestion question) {
        /* TODO: To be implemented by the student */

        // Generates random transaction ID
        int ID = random.nextInt(0x10000);

        // Creates the DNSMessage query
        DNSMessage query = new DNSMessage((short)ID);

        // Adds the question to the query
        query.addQuestion(question);

        return query;
    }

    /**
     * Parses and processes a response received by a nameserver.
     * If the reply contains a non-zero Rcode value, then throw a DNSErrorException.
     * Adds all resource records found in the response message to the cache.
     * Calls methods in the verbose object at appropriate points of the processing sequence. Must be able
     * to properly parse records of the types: A, AAAA, NS, CNAME and MX (the priority field for MX may be ignored). Any
     * other unsupported record type must create a record object with the data represented as a hex string (see method
     * byteArrayToHexString).
     *
     * @param message The DNSMessage received from the server.
     * @return A set of all resource records received in the response.
     * @throws DNSErrorException if the Rcode value in the reply header is non-zero
     */
    public Set<ResourceRecord> processResponse(DNSMessage message) throws DNSErrorException {
        /* TODO: To be implemented by the student */

        // Initializing all the variables we need
        int ID = message.getID();
        boolean AA = message.getAA();
        int RCode = message.getRcode();

        if (RCode != 0) {
            // If the reply contains a non-zero RCode value, then throw a DNSErrorException.
            throw new DNSErrorException("RCode is " + RCode);

        } else {

            // Calls methods for verbose object at appropriate points
            verbose.printResponseHeaderInfo(ID, AA, RCode);
            int QD = message.getQDCount();

            for (int i = 0; i < QD; i++) {
                // Skips all the questions in the ByteBuffer
                message.getQuestion();
            }

            Set<ResourceRecord> set = new HashSet<ResourceRecord>();

            // Calls methods for verbose object at appropriate points
            int AN = message.getANCount();
            verbose.printAnswersHeader(AN);

            for (int i = 0; i < AN; i++) {

                // Processes all the Authoritative ResourceRecords

                ResourceRecord rr = message.getRR();
                int RT = rr.getRecordType().getCode();
                int RC = rr.getRecordClass().getCode();
                verbose.printIndividualResourceRecord(rr, RT, RC);

                // Adds to the set and cache
                set.add(rr);
                cache.addResult(rr);

            }

            // Calls methods for verbose object at appropriate points
            int NS = message.getNSCount();
            verbose.printNameserversHeader(NS);

            for (int i = 0; i < NS; i++) {

                // Processes all the Name Server ResourceRecords

                ResourceRecord rr = message.getRR();
                int RT = rr.getRecordType().getCode();
                int RC = rr.getRecordClass().getCode();
                verbose.printIndividualResourceRecord(rr, RT, RC);

                // Adds to the set and cache
                set.add(rr);
                cache.addResult(rr);

            }

            // Calls methods for verbose object at appropriate points
            int AR = message.getARCount();
            verbose.printAdditionalInfoHeader(AR);


            for (int i = 0; i < AR; i++) {

                // Processes all the Additional ResourceRecords

                ResourceRecord rr = message.getRR();
                int RT = rr.getRecordType().getCode();
                int RC = rr.getRecordClass().getCode();
                verbose.printIndividualResourceRecord(rr, RT, RC);

                // Adds to the set and cache
                set.add(rr);
                cache.addResult(rr);

            }

            return set;

        }

    }

    public static class DNSErrorException extends Exception {
        public DNSErrorException(String msg) {
            super(msg);
        }
    }
}
