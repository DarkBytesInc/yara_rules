rule Win_Worm_Mytob_214
{
strings:
	$a0 = { 395a2a7957c425912cd7cedb6fe1cc07ebe6982481b26406d7376870512eacabe1c083479cc690be8272343d4e2e19d4fd50ed0c5c932781108787e6650e828c6e8a26d0038b3ee3e1b9b307020a138b5f547691e7d0493cf373eae8cd0b38b03e74766644f17c34335f5a4750b4bbe4fed6ffc8fb837688fe581b98de3e568f2ac347dd35dd9d6255178f70575248ef290f72f75ca2 }

condition:
	$a0
}

        