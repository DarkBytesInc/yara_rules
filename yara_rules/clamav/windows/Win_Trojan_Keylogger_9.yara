rule Win_Trojan_Keylogger_9
{
strings:
	$a0 = { 3046bb45712f885044456a31d99228b838915cc6576b6eb20e4c89f3ebe3c13279d98d17ef367c9e0b0683b45c2fe7aa57ee28cc16340ade797f87957657939f43db6e25678f1b2cf8f62541a2c0a29bc5fc577e72c6607e24ded449e637d5dea29d6044f6b010b5e8f56e434249956d67baa5d146ee143798b34ff96ece15d6dbc24e0485142d9f130a262dac53cf76f55daebddafe }

condition:
	$a0
}

        