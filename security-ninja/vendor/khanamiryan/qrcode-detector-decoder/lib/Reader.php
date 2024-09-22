<?php

namespace WPSecurityNinja\Plugin\Zxing;

interface Reader
{
	public function decode(BinaryBitmap $image);

	public function reset();
}
