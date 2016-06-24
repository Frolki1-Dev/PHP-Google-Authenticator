<?php
	namespace Google\Authenticator;

	use Base32\Base32;
	use Endroid\QrCode\QrCode;

	class Authenticator
	{
		protected $codeLength;
		protected $secretLength;
		protected $pinModulo;

		/**
		 * Authenticator constructor.
		 *
		 * @param int $codeLength
		 * @param int $secretLength
		 */
		public function __construct($codeLength = 6, $secretLength = 10)
		{
			$this->codeLength = $codeLength;
			$this->secretLength = $secretLength;
			$this->pinModulo = pow(10, $codeLength);
		}

		/**
		 * Generate a secret code
		 *
		 * @return string
		 */
		public function generateSecret()
		{
			$secret = "";
			for ($i = 1; $i <= $this->secretLength; $i++) {
				$c = rand(0, 255);
				$secret .= pack('c', $c);
			}
			return Base32::encode($secret);
		}

		/**
		 * Get the QR Code
		 *
		 * @param string $user
		 * @param string $hostname
		 * @param string $secret
		 * @param int    $dimension
		 *
		 * @return string;
		 */
		public function getQRCode($user, $hostname, $secret, $dimension = 200)
		{
			$endpoint = "otpauth://totp/" . $user . "?secret=" . $secret . "&issuer=" . $hostname;

			$qrCode = new QrCode();
			$code = $qrCode
				->setText($endpoint)
				->setSize($dimension)
				->setErrorCorrection('high')
				->getDataUri();

			return $code;
		}

		/**
		 * Get the code from the time and secret
		 *
		 * @param string   $secret
		 * @param int|null $time
		 *
		 * @return string
		 */
		public function getCode($secret, $time = null)
		{
			if (!$time) {
				$time = floor(time() / 30);
			}

			$secret = Base32::decode($secret);

			$time = pack('N', $time);
			$time = str_pad($time, 8, chr(0), STR_PAD_LEFT);

			$hash = hash_hmac('sha1', $time, $secret, true);
			$offset = ord(substr($hash, -1));
			$offset = $offset & 0xF;

			$tHash = $this->hashToInt($hash, $offset) & 0x7FFFFFFF;
			$pin = str_pad($tHash % $this->pinModulo, 6, "0", STR_PAD_LEFT);

			return $pin;
		}

		/**
		 * Check if the code from the user is correct
		 *
		 * @param string $secret
		 * @param string $code
		 *
		 * @return bool
		 */
		public function checkCode($secret, $code)
		{
			$time = floor(time() / 30);
			for ($i = -1; $i <= 1; $i++) {
				if($this->getCode($secret, $time + $i) == $code) {
					return true;
				}
			}
			return false;
		}

		/**
		 * @param string $bytes
		 * @param int    $start
		 *
		 * @return int
		 */
		private function hashToInt($bytes, $start)
		{
			$in = substr($bytes, $start, (strlen($bytes) - $start));
			$val = unpack('N', substr($in, 0, 4));
			return $val[1];
		}
	}