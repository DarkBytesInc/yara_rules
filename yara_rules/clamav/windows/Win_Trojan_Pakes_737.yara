rule Win_Trojan_Pakes_737
{
strings:
	$a0 = { 15df12fba1824f67e430399b9ad668329513f92bb9c7bfe295abffb278a9355d7e1cf395beca2a48aac232b01ac10da5916b3fd05f7e34a28a8823b1eb0f3890f6aef6b59aaba63249b067e42b9d44d5447b3324883d40ca554bf23daeccb80b0db09eab2b5174de8a2849adaf5f162a15781b8b73440e36be362b73a9aa2ab87b501f796cb6feaf632fc49b }

condition:
	$a0
}

        