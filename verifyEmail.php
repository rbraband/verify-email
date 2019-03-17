<?php

/**
 * Class to check up e-mail
 *
 * @author Konstantin Granin <kostya@granin.me>
 * @copyright Copyright (c) 2015, Konstantin Granin
 * @copyright Copyright (c) 2019, Roland Braband
 */
class verifyEmail {

    protected $stream = false;

    /**
     * SMTP port number
     * @var int
     */
    protected $port = 25;

    /**
     * email address for request
     * @var string 
     */
    protected $from = 'root@localhost';

    /**
     * The connection timeout, in seconds.
     * @var int
     */
    protected $max_connection_timeout = 3;

    /**
     * Timeout value on stream, in seconds.
     * @var int
     */
    protected $stream_timeout = 5;

    /**
     * Wait timeout on stream, in rounds per stream_timeout.
     * * 0 - not wait
     * @var int
     */
    protected $stream_timeout_wait = 12;

    /**
     * Whether to throw exceptions for errors.
     * @type boolean
     * @access protected
     */
    protected $exceptions = false;
    
    /**
     * The number of errors encountered.
     * @type integer
     * @access protected
     */
    protected $error_count = 0;
    
    /**
     * The language of error message.
     * @type integer
     * @access protected
     */
    protected $error_lang = 'de';
    
    /**
     * The list of i18n errors.
     * @type array
     * @access protected
     */
    protected $error_i18n = array(
        'invalid_adress' => array(
            'en' => 'Invalid address: %s',
            'de' => 'Ungültige Adresse: %s'
        ),
        'mx_not_found' => array(
            'en' => 'MX records not found or an error occurred',
            'de' => 'MX-Info nicht gefunden oder Fehler aufgetreten'
        ),
        'dns_not_found' => array(
            'en' => 'DNS records not found or an error occurred',
            'de' => 'DNS-Info nicht gefunden oder Fehler aufgetreten'
        ),
        'incorrect_adress' => array(
            'en' => '%s incorrect e-mail',
            'de' => '%s falsche E-Mail'
        ),
        'correct_adress' => array(
            'en' => '%s is correct e-mail',
            'de' => '%s korrekte E-Mail'
        ),
        'problem_socket' => array(
            'en' => 'Problem initializing the socket',
            'de' => 'Problem bei der Initialisierung des Sockets'
        ),
        'connection_fails' => array(
            'en' => 'All connection fails',
            'de' => 'Alle Verbindungen fehlgeschlagen'
        ),
        'server_black_listed' => array(
            'en' => 'Server is black listed: %s',
            'de' => 'Server ist auf der Blacklist: %s'
        ),
        'address_accepted' => array(
            'en' => 'Success (%s): Address accepted',
            'de' => 'Erfolg (%s): Adresse akzeptiert'
        ),
        'not_checked' => array(
            'en' => 'Warning (%s): Address not checked',
            'de' => 'Warnung (%s): Adresse nicht geprüft'
        ),
        'address_invalid' => array(
            'en' => 'Error (%s): Address invalid',
            'de' => 'Fehler (%s): Adresse ungültig'
        )
    );

    /**
     * class debug output mode.
     * @type boolean
     */
    public $Debug = false;
    
    /**
     * check completed, mail okay.
     * @type boolean
     */
    public $Completed = false;

    /**
     * How to handle debug output.
     * Options:
     * * `echo` Output plain-text as-is, appropriate for CLI
     * * `html` Output escaped, line breaks converted to `<br>`, appropriate for browser output
     * * `log` Output to error log as configured in php.ini
     * @type string
     */
    public $Debugoutput = 'echo';

    /**
     * SMTP RFC standard line ending.
     */
    const CRLF = "\r\n";

    /**
     * Holds the last error message.
     * @type string
     */
    public $ErrorInfo = '';

    /**
     * Holds all messages.
     * @type string
     */
    public $MessageStack = array();

    /**
     * Constructor.
     * @param boolean $exceptions Should we throw external exceptions?
     */
    public function __construct($exceptions = false) {
        $this->exceptions = (boolean) $exceptions;
    }

    /**
     * Set email address for SMTP request
     * @param string $email Email address
     */
    public function setEmailFrom($email) {
        if (!self::validate($email)) {
            $this->set_error('invalid_adress', $email);
            $this->edebug($this->ErrorInfo);
            if ($this->exceptions) {
                throw new verifyEmailException($this->ErrorInfo);
            }
        }
        $this->from = $email;
    }

    /**
     * Set connection timeout, in seconds.
     * @param int $seconds
     */
    public function setConnectionTimeout($seconds) {
        if ($seconds > 0) {
            $this->max_connection_timeout = (int) $seconds;
        }
    }

    /**
     * Sets the timeout value on stream, expressed in the seconds
     * @param int $seconds
     */
    public function setStreamTimeout($seconds) {
        if ($seconds > 0) {
            $this->stream_timeout = (int) $seconds;
        }
    }
    
    /**
     * Validate email address.
     * @param string $email
     * @return boolean  True if valid.
     */
    public function isValid($email) {
        return $this->validate($email);
    }

    public function setStreamTimeoutWait($rounds) {
        if ($rounds >= 0) {
            $this->stream_timeout_wait = (int) $rounds;
        }
    }

    /**
     * Validate email address.
     * @param string $email
     * @return boolean  True if valid.
     */
    public static function validate($email) {
        return (boolean) ($email === filter_var($email, FILTER_SANITIZE_EMAIL) && filter_var($email, FILTER_VALIDATE_EMAIL));
    }
    
    /**
     * Simple lookup for blacklisted IP against multiple DNSBLs at once
     */
    public function isBlackListed($ip) {
        $result = array();
        $dnsbl_check = array("bl.spamcop.net",
                             "list.dsbl.org",
                             "sbl.spamhaus.org");
        
        if (filter_var($ip, FILTER_VALIDATE_IP) === FALSE)
            $ip = gethostbyname($ip);
            
        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            $reverse_ip = implode(".", array_reverse(explode(".", $ip)));
            foreach ($dnsbl_check as $host) {
                if (checkdnsrr($reverse_ip . "." . $host . ".", "A")) {
                    $result[] = array($host, $reverse_ip . "." . $host);
                }
            }
            return ((empty($result)) ? FALSE : $result);
       }
       return FALSE;
    }

    /**
     * Get array of MX records for host. Sort by weight information.
     * @param string $hostname The Internet host name.
     * @return array Array of the MX records found.
     */
    public function getMXrecords($hostname) {
        $mxhosts = array();
        $mxweights = array();

        if (getmxrr($hostname, $mxhosts, $mxweights) === FALSE) {
            $this->set_error('mx_not_found');
            $this->edebug($this->ErrorInfo);
            if (checkdnsrr($hostname, 'A') === FALSE) {
                $this->set_error('dns_not_found');
                $this->edebug($this->ErrorInfo);
                return $mxhosts;
            }
        } else {
            array_multisort($mxweights, $mxhosts);
        }
        /**
         * Add A-record as last chance (e.g. if no MX record is there).
         * Thanks Nicht Lieb.
         * @link http://www.faqs.org/rfcs/rfc2821.html RFC 2821 - Simple Mail Transfer Protocol
         */
        if (empty($mxhosts)) {
            array_unshift($mxhosts, $hostname);
        }
        return $mxhosts;
    }

    /**
     * Parses input string to array(0=>user, 1=>domain)
     * @param string $email
     * @param boolean $only_domain
     * @return string|array
     * @access private
     */
    public static function parse_email($email, $only_domain = TRUE) {
        sscanf($email, "%[^@]@%s", $user, $domain);
        return ($only_domain) ? $domain : array($user, $domain);
    }

    /**
     * Add an error message to the error container.
     * @access protected
     * @param string $msg
     * @return void
     */
    protected function set_error($msg) {
        $numargs = func_num_args();
        $msg = (array_key_exists(strtolower($msg), $this->error_i18n)) ?
            $this->error_i18n[strtolower($msg)][$this->error_lang] : $msg;
        if ($numargs > 1) {
            $msg_args = func_get_args();
            array_shift($msg_args);
            $msg = vsprintf($msg, $msg_args);
        }
        $this->error_count++;
        $this->ErrorInfo = $msg;
    }

    /**
     * Check if an error occurred.
     * @access public
     * @return boolean True if an error did occur.
     */
    public function isError() {
        return ($this->error_count > 0);
    }

    /**
     * Output debugging info
     * Only generates output if debug output is enabled
     * @see verifyEmail::$Debugoutput
     * @see verifyEmail::$Debug
     * @param string $str
     */
    protected function edebug($str) {
        if ($str == '')
            return;
        
        array_push($this->MessageStack, $str);
        if (!$this->Debug) {
            return;
        }
        switch ($this->Debugoutput) {
            case 'log':
                //Don't output, just log
                error_log($str);
                break;
            case 'html':
                //Cleans up output a bit for a better looking, HTML-safe output
                echo htmlentities(
                        preg_replace('/[\r\n]+/', '', $str), ENT_QUOTES, 'UTF-8'
                )
                . "<br>\n";
                break;
            case 'echo':
                //Normalize line breaks
                $str = preg_replace('/(\r\n|\r|\n)/ms', "\n", $str);
                echo gmdate('Y-m-d H:i:s') . "\t" . str_replace(
                        "\n", "\n                   \t                  ", trim($str)
                ) . "\n";
                break;
            default:
                //Don't output
                break;
        }
    }

    /**
     * check up e-mail
     * @param string $email Email address
     * @return boolean True if the valid email also exist
     */
    public function check($email) {
        $code = '000';
        $result = FALSE;
        $response = NULL;
        $this->Completed = FALSE;

        if (!self::validate($email)) {
            $this->set_error('incorrect_adress', $email);
            $this->edebug($this->ErrorInfo);
            if ($this->exceptions) {
                throw new verifyEmailException($this->ErrorInfo);
            }
            return FALSE;
        }
        
        $this->set_error('correct_adress', $email);
        $this->edebug($this->ErrorInfo);
            
        $this->error_count = 0; // Reset errors
        $this->stream = FALSE;

        $mxs = $this->getMXrecords(self::parse_email($email));
        $timeout = ceil($this->max_connection_timeout / count($mxs));
            
        foreach ($mxs as $host) {
            /**
             * suppress error output from stream socket client...
             * Thanks Michael.
             */
            $this->stream = @stream_socket_client("tcp://" . $host . ":" . $this->port, $errno, $errstr, $timeout);
            if ($this->stream === FALSE) {
                if ($errno == 0) {
                    $this->set_error('problem_socket');
                    $this->edebug($this->ErrorInfo);
                    if ($this->exceptions) {
                        throw new verifyEmailException($this->ErrorInfo);
                    }
                    return FALSE;
                } else {
                    $this->edebug($host . ":" . $errstr);
                }
            } else {
                stream_set_timeout($this->stream, $this->stream_timeout);
                stream_set_blocking($this->stream, 1);
                
                $response = $this->_streamResponse();
                $code = $this->_streamCode($response);

                /* 220 Ok */
                if ($code == '220') {
                    $this->edebug("Connection success {$host}");
                    break;
                } else {
                    fclose($this->stream);
                    $this->stream = FALSE;
                    $this->edebug("Connection fails {$host}");
                }
            }
        }

        if ($this->stream === FALSE) {
            $this->set_error('connection_fails');
            $this->edebug($this->ErrorInfo);
            if ($code == '421' || $code == '451' || $code == '554' || ($code == '550' && 
                (preg_match("/No PTR Record/i", $response) || preg_match("/Reverse lookup/i", $response) || preg_match("/Protocol error/i", $response) || preg_match("/Sender verification/i", $response) || preg_match("/Relay not permitted/i", $response)))) {
                /* 
                   421 Service not available / Too much load
                   451 Please try again later
                   550 No PTR Record
                   550 Reverse lookup
                   550 Protocol error
                   550 Relay not permitted
                   554 You are not allowed to connect
                */
                $this->set_error('not_checked', $code);
                $this->edebug($this->ErrorInfo);
                return TRUE;
            } else {
                $this->set_error('address_invalid', $code);
                $this->edebug($this->ErrorInfo);
                
                if ($this->exceptions) {
                    throw new verifyEmailException($this->ErrorInfo);
                }
            }
            return FALSE;
        }
        
        $ibl = $this->isBlackListed($host);
        if ($ibl !== FALSE) {
            $this->set_error('server_black_listed', implode(', ', $ibl));
            $this->edebug($this->ErrorInfo);
            if ($this->exceptions) {
                throw new verifyEmailException($this->ErrorInfo);
            }
            fclose($this->stream);
            return FALSE;
        }

        if (!(
            $this->_streamQuery("HELO " . self::parse_email($this->from)) &&
            !!($response = $this->_streamResponse()) &&
            $this->_streamQuery("MAIL FROM: <{$this->from}>") &&
            !!($response = $this->_streamResponse()) &&
            $this->_streamQuery("RCPT TO: <{$email}>")
            )
        )   return $this->_parseCode($response);
        
        $response = $this->_streamResponse();
        
        //$this->_streamResponse();
        $this->_streamQuery("RSET");
        //$this->_streamResponse();
        $this->_streamQuery("QUIT");

        fclose($this->stream);

        return $this->_parseCode($response);
    }
    
    protected function _parseCode($response) {
        $code = $this->_streamCode($response);
        
        switch ($code) {
            case '250':
            case '251':
            case '252':
                /**
                 * http://www.ietf.org/rfc/rfc0821.txt
                 * 250 Requested mail action okay, completed
                 * 251	User not local; will forward to <forward-path>
                 * 252	Cannot VRFY user, but will accept message and attempt delivery
                 * email address was accepted
                 */
                $this->set_error('address_accepted', $code);
                $this->edebug($this->ErrorInfo);
                $this->Completed = TRUE;
                return TRUE;
            case '999':
            case '421':
            case '450':
            case '451':
            case '452':
            case '521':
            case '530':
            case '551':
            case '552':
            case '554':
                /**
                 * http://www.ietf.org/rfc/rfc0821.txt
                 * 421 Service not available / Too much load
                 * 450 Requested action not taken: the remote mail server
                 *     does not want to accept mail from your server for
                 *     some reason (IP address, blacklisting, etc..)
                 *     Thanks Nicht Lieb.
                 * 451 Requested action aborted: local error in processing
                 * 452 Requested action not taken: insufficient system storage
                 * email address was greylisted (or some temporary error occured on the MTA)
                 * 521 5.5.1 : Protocol error
                 * 530	     : Access denied
                 * 551	     : User not local
                 * 552	     : Requested mail action aborted
                 * 554 5.7.1 : Transaction failed
                 * 554 5.7.1 : You are not allowed to connect.
                 * i believe that e-mail exists
                 */
                $this->set_error('not_checked', $code);
                $this->edebug($this->ErrorInfo);
                return TRUE;
            case '550':
                /**
                 * 550       : Sender verification is required but failed
                 * 550       : Reverse lookup of your IP failed
                 * 550 5.1.0 : Address rejected.
                 * 550 5.1.1 : The email account that you tried to reach does not exist
                 * 550 5.1.1 : Recipient rejected
                 * 550 5.1.1 : User unknown
                 * 550 5.1.1 : Recipient address rejected: User unknown in virtual alias table
                 * 550 5.2.0 : mailbox unavailable
                 * 550 5.5.0 : IP blacklisted
                 * 550 5.5.1 : Protocol error
                 *     does not want to accept your request for
                 *     some reason (Tunneling, Pipelining, TLS, etc..)
                 *     we can recheck later!
                 * 550 7.5.1 : No PTR Record
                 * i believe that e-mail does not exists!
                 * ... exceptions see below
                 */
                if (preg_match("/No PTR Record/i", $response) || preg_match("/Reverse lookup/i", $response) || preg_match("/Protocol error/i", $response) || preg_match("/Sender verification/i", $response) || preg_match("/Relay not permitted/i", $response)) {
                    $this->set_error('not_checked', $code);
                    $this->edebug($this->ErrorInfo);
                    return TRUE;
                }
            default :
                $this->set_error('address_invalid', $code);
                $this->edebug($this->ErrorInfo);
                return FALSE;
        }
    }

    /**
     * writes the contents of string to the file stream pointed to by handle 
     * If an error occurs, returns FALSE.
     * @access protected
     * @param string $string The string that is to be written
     * @return string Returns a result code, as an integer. 
     */
    protected function _streamQuery($query) {
        $this->edebug($query);
        if (!((@stream_socket_sendto($this->stream, $query . self::CRLF)) !== -1)) {
            $this->set_error('socket_error', socket_strerror(socket_last_error()));
            $this->edebug($this->ErrorInfo);
            if ($this->exceptions) {
                throw new verifyEmailException($this->ErrorInfo);
            }
            return FALSE;
        }
        return TRUE;
    }

    /**
     * Reads all the line long the answer and analyze it.
     * If an error occurs, returns FALSE
     * @access protected
     * @return string Response
     */
    protected function _streamResponse($timed = 1) {
        
        $_suffix = '';
        do {
            $buffer = stream_get_line($this->stream, 1024, self::CRLF);
            $reply .= $buffer . $_suffix;
            $_suffix = "\n";
            $status = stream_get_meta_data($this->stream);
        } while (!feof($this->stream) && $status['unread_bytes'] > 0);
     
        if ($buffer === FALSE && $status['timed_out'] && $timed <= $this->stream_timeout_wait) {
            return $this->_streamResponse(($timed++));
        }
        
        else if (empty($reply) && !empty($status['timed_out'])) {
            $timed_stream_timeout = $timed * $this->stream_timeout;
            $this->edebug("Timed out while waiting for data! (timeout {$timed_stream_timeout} seconds)");
        }

        $this->edebug($reply);
        return $reply;
    }

    /**
     * Get Response code from Response
     * @param string $str
     * @return string
     */
    protected function _streamCode($str) {
        preg_match('/^(?<code>[0-9]{3})(\s|-)(.*)$/ims', $str, $matches);
        $code = isset($matches['code']) ? $matches['code'] : '999';
        return $code;
    }

}

/**
 * verifyEmail exception handler
 */
class verifyEmailException extends Exception {

    /**
     * Prettify error message output
     * @return string
     */
    public function errorMessage() {
        //$errorMsg = '<strong>' . $this->getMessage() . "</strong><br />\n";
        $errorMsg = $this->getMessage();
        return $errorMsg;
    }

}
