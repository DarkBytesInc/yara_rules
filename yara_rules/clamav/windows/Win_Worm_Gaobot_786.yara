rule Win_Worm_Gaobot_786
{
strings:
	$a0 = { 66e87fb17b98adb043beecff4cc8ad4ca227416dc7d3bc9056242798efc333ecc004fd003e92aabee5a0db6536dfea70870e0814a67c9cbf043a81034dc8cdb4c2e3505efe5f8780bf2a2aab1cf2e212fcb91e655fa5a972df230287d852fa38e938bd28e0145d5a474969c4cc92af1e }

condition:
	$a0
}

        
