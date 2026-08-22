; ModuleID = '173fz22kkmkk4ifnyupi5nv17'
source_filename = "173fz22kkmkk4ifnyupi5nv17"
target datalayout = "e-m:w-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-windows-msvc"

%"core::mem::maybe_uninit::MaybeUninit<(misanthropic::prompt::message::Role, &str)>" = type { [3 x i64] }
%"misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>" = type { %"misanthropic::prompt::message::Content", i8, [7 x i8] }
%"misanthropic::prompt::message::Content" = type { %"alloc::vec::Vec<misanthropic::prompt::message::Block>" }
%"alloc::vec::Vec<misanthropic::prompt::message::Block>" = type { %"alloc::raw_vec::RawVec<misanthropic::prompt::message::Block>", i64 }
%"alloc::raw_vec::RawVec<misanthropic::prompt::message::Block>" = type { %"alloc::raw_vec::RawVecInner", %"core::marker::PhantomData<misanthropic::prompt::message::Block>" }
%"alloc::raw_vec::RawVecInner" = type { i64, ptr, %"alloc::alloc::Global" }
%"alloc::alloc::Global" = type {}
%"core::marker::PhantomData<misanthropic::prompt::message::Block>" = type {}
%"misanthropic::prompt::message::Block" = type { i64, [25 x i64] }

@alloc_5a8fdd84b3281310cbf6b74bb6bf0065 = private unnamed_addr constant [218 x i8] c"unsafe precondition(s) violated: slice::get_unchecked_mut requires that the index is within the slice\0A\0AThis indicates a bug in the program. This Undefined Behavior check is optional, and cannot be relied on for safety.", align 1
@alloc_31365cfefba383c4d2bf6b6a04cc10aa = private unnamed_addr constant [17 x i8] c"capacity overflow", align 1
@alloc_11d257f5ed6cc7fc38feaa801053bac6 = private unnamed_addr constant <{ ptr, [8 x i8] }> <{ ptr @alloc_31365cfefba383c4d2bf6b6a04cc10aa, [8 x i8] c"\11\00\00\00\00\00\00\00" }>, align 8
@anon.9bb7cee0307838987e4b4b15e8b33297.0 = private unnamed_addr constant <{ [8 x i8], [8 x i8] }> <{ [8 x i8] zeroinitializer, [8 x i8] undef }>, align 8
@alloc_8897516554addc49c72bdeabfbff2df3 = private unnamed_addr constant [109 x i8] c"C:\\Users\\hanna\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f\\misanthropic-1.0.0-alpha.16\\src\\client.rs", align 1
@alloc_cb949ee21930fa9ac27f98d4a4eed7ed = private unnamed_addr constant <{ ptr, [16 x i8] }> <{ ptr @alloc_8897516554addc49c72bdeabfbff2df3, [16 x i8] c"m\00\00\00\00\00\00\00^\00\00\00\1B\00\00\00" }>, align 8
@alloc_16157024dd92dd2dc2624dbf6332a09b = private unnamed_addr constant [6 x i8] c"stream", align 1
@alloc_a442c2025036816d4885b50e4d2c7d48 = private unnamed_addr constant <{ ptr, [16 x i8] }> <{ ptr @alloc_8897516554addc49c72bdeabfbff2df3, [16 x i8] c"m\00\00\00\00\00\00\00\22\02\00\00\0D\00\00\00" }>, align 8
@alloc_56e9bd399e30d3413bf7eef70d31cd4b = private unnamed_addr constant <{ ptr, [16 x i8] }> <{ ptr @alloc_8897516554addc49c72bdeabfbff2df3, [16 x i8] c"m\00\00\00\00\00\00\00!\02\00\00\18\00\00\00" }>, align 8
@alloc_9ff19f39cc9b55a493c0422322b7f3f4 = private unnamed_addr constant <{ ptr, [16 x i8] }> <{ ptr @alloc_8897516554addc49c72bdeabfbff2df3, [16 x i8] c"m\00\00\00\00\00\00\00 \02\00\00\05\00\00\00" }>, align 8
@alloc_8add1a43e0a2ee2ff94337595fe8e6b5 = private unnamed_addr constant [33 x i8] c"Expected a stream, got a message.", align 1
@alloc_97a13f3d19b3fa2879ca5b761b6eb98d = private unnamed_addr constant <{ ptr, [16 x i8] }> <{ ptr @alloc_8897516554addc49c72bdeabfbff2df3, [16 x i8] c"m\00\00\00\00\00\00\00$\02\00\005\00\00\00" }>, align 8
@alloc_9659f738698ca9b8cf068074f840c3cd = private unnamed_addr constant [109 x i8] c"C:\\Users\\hanna\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f\\misanthropic-1.0.0-alpha.16\\src\\prompt.rs", align 1
@alloc_87355aedd51e74f601f1a2bd7729f10f = private unnamed_addr constant <{ ptr, [16 x i8] }> <{ ptr @alloc_9659f738698ca9b8cf068074f840c3cd, [16 x i8] c"m\00\00\00\00\00\00\00\CA\01\00\00\09\00\00\00" }>, align 8
@alloc_c86808924c6a6c540af584c966c7c14f = private unnamed_addr constant [117 x i8] c"C:\\Users\\hanna\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f\\misanthropic-1.0.0-alpha.16\\src\\prompt\\message.rs", align 1
@alloc_e333a51a7d3d4141e0beb547b79b3281 = private unnamed_addr constant <{ ptr, [16 x i8] }> <{ ptr @alloc_c86808924c6a6c540af584c966c7c14f, [16 x i8] c"u\00\00\00\00\00\00\00]\02\00\00\1E\00\00\00" }>, align 8
@alloc_3e1ebac14318b612ab4efabc52799932 = private unnamed_addr constant [186 x i8] c"unsafe precondition(s) violated: usize::unchecked_add cannot overflow\0A\0AThis indicates a bug in the program. This Undefined Behavior check is optional, and cannot be relied on for safety.", align 1
@alloc_fc658c4d7f35ad2dbc3f0a1b382d749d = private unnamed_addr constant [80 x i8] c"/rustc/6b00bc3880198600130e1cf62b8f8a93494488cc\\library\\core\\src\\ops\\function.rs", align 1
@alloc_c08768be04b52678f33214e18ddf67cd = private unnamed_addr constant <{ ptr, [16 x i8] }> <{ ptr @alloc_fc658c4d7f35ad2dbc3f0a1b382d749d, [16 x i8] c"P\00\00\00\00\00\00\00\A6\00\00\00\05\00\00\00" }>, align 8
@alloc_2dff866d8f4414dd3e87cf8872473df8 = private unnamed_addr constant [227 x i8] c"unsafe precondition(s) violated: ptr::read_volatile requires that the pointer argument is aligned and non-null\0A\0AThis indicates a bug in the program. This Undefined Behavior check is optional, and cannot be relied on for safety.", align 1
@alloc_fad0cd83b7d1858a846a172eb260e593 = private unnamed_addr constant [42 x i8] c"is_aligned_to: align is not a power-of-two", align 1
@alloc_e92e94d0ff530782b571cfd99ec66aef = private unnamed_addr constant <{ ptr, [8 x i8] }> <{ ptr @alloc_fad0cd83b7d1858a846a172eb260e593, [8 x i8] c"*\00\00\00\00\00\00\00" }>, align 8
@alloc_f1683e5e7f5ab4224bf90c2b037ec7a5 = private unnamed_addr constant [81 x i8] c"/rustc/6b00bc3880198600130e1cf62b8f8a93494488cc\\library\\core\\src\\ptr\\const_ptr.rs", align 1
@alloc_d5565c3c200d27d008540d6a6ddd052a = private unnamed_addr constant <{ ptr, [16 x i8] }> <{ ptr @alloc_f1683e5e7f5ab4224bf90c2b037ec7a5, [16 x i8] c"Q\00\00\00\00\00\00\00\C4\05\00\00\0D\00\00\00" }>, align 8
@alloc_560a59ed819b9d9a5841f6e731c4c8e5 = private unnamed_addr constant [210 x i8] c"unsafe precondition(s) violated: NonNull::new_unchecked requires that the pointer is non-null\0A\0AThis indicates a bug in the program. This Undefined Behavior check is optional, and cannot be relied on for safety.", align 1
@alloc_64e308ef4babfeb8b6220184de794a17 = private unnamed_addr constant [221 x i8] c"unsafe precondition(s) violated: hint::assert_unchecked must never be called when the condition is false\0A\0AThis indicates a bug in the program. This Undefined Behavior check is optional, and cannot be relied on for safety.", align 1
@alloc_bf434f0723b4210d44573f2a2f80bbb3 = private unnamed_addr constant [88 x i8] c"/rustc/6b00bc3880198600130e1cf62b8f8a93494488cc\\library\\core\\src\\iter\\traits\\iterator.rs", align 1
@alloc_6c46f8590da398a638f194d8c62f4d95 = private unnamed_addr constant <{ ptr, [16 x i8] }> <{ ptr @alloc_bf434f0723b4210d44573f2a2f80bbb3, [16 x i8] c"X\00\00\00\00\00\00\00\D1\07\00\00\09\00\00\00" }>, align 8
@alloc_1be5ea12ba708d9a11b6e93a7d387a75 = private unnamed_addr constant [281 x i8] c"unsafe precondition(s) violated: Layout::from_size_align_unchecked requires that align is a power of 2 and the rounded-up allocation size does not exceed isize::MAX\0A\0AThis indicates a bug in the program. This Undefined Behavior check is optional, and cannot be relied on for safety.", align 1
@alloc_ed94656ef76aaf075250cb4cc743419f = private unnamed_addr constant [77 x i8] c"/rustc/6b00bc3880198600130e1cf62b8f8a93494488cc\\library\\core\\src\\ub_checks.rs", align 1
@alloc_413737a8117e59d7685b5a9a1a04e06a = private unnamed_addr constant <{ ptr, [16 x i8] }> <{ ptr @alloc_ed94656ef76aaf075250cb4cc743419f, [16 x i8] c"M\00\00\00\00\00\00\00\86\00\00\006\00\00\00" }>, align 8
@alloc_a28e8c8fd5088943a8b5d44af697ff83 = private unnamed_addr constant [279 x i8] c"unsafe precondition(s) violated: slice::from_raw_parts requires the pointer to be aligned and non-null, and the total size of the slice not to exceed `isize::MAX`\0A\0AThis indicates a bug in the program. This Undefined Behavior check is optional, and cannot be relied on for safety.", align 1
@vtable.0 = private unnamed_addr constant <{ ptr, [16 x i8], ptr }> <{ ptr @"_ZN4core3ptr48drop_in_place$LT$misanthropic..client..Error$GT$17h0315295c7eac22e8E", [16 x i8] c"0\00\00\00\00\00\00\00\08\00\00\00\00\00\00\00", ptr @"_ZN64_$LT$misanthropic..client..Error$u20$as$u20$core..fmt..Debug$GT$3fmt17h64ce421a790cda37E" }>, align 8
@alloc_00ae4b301f7fab8ac9617c03fcbd7274 = private unnamed_addr constant [43 x i8] c"called `Result::unwrap()` on an `Err` value", align 1
@vtable.1 = private unnamed_addr constant <{ ptr, [16 x i8], ptr }> <{ ptr @"_ZN4core3ptr57drop_in_place$LT$misanthropic..prompt..TurnOrderError$GT$17h7350f3462e7bc41cE", [16 x i8] c"@\00\00\00\00\00\00\00\08\00\00\00\00\00\00\00", ptr @"_ZN73_$LT$misanthropic..prompt..TurnOrderError$u20$as$u20$core..fmt..Debug$GT$3fmt17h351c0bf5472a2e32E" }>, align 8
@vtable.2 = private unnamed_addr constant <{ [24 x i8], ptr }> <{ [24 x i8] c"\00\00\00\00\00\00\00\00\08\00\00\00\00\00\00\00\08\00\00\00\00\00\00\00", ptr @"_ZN85_$LT$misanthropic..key..unencrypted..InvalidKeyLength$u20$as$u20$core..fmt..Debug$GT$3fmt17h1ca2bc38c221c87cE" }>, align 8
@__rust_no_alloc_shim_is_unstable = external global i8
@alloc_7010aabf0bbde7181fd2cd0d0ef3d0b6 = private unnamed_addr constant [4 x i8] c"HTTP", align 1
@vtable.3 = private unnamed_addr constant <{ [24 x i8], ptr }> <{ [24 x i8] c"\00\00\00\00\00\00\00\00\08\00\00\00\00\00\00\00\08\00\00\00\00\00\00\00", ptr @"_ZN42_$LT$$RF$T$u20$as$u20$core..fmt..Debug$GT$3fmt17h61ed4aaa3ee90e6fE" }>, align 8
@alloc_4cf7911ffc1fa65c3bf9af4755f6af39 = private unnamed_addr constant [5 x i8] c"Parse", align 1
@vtable.4 = private unnamed_addr constant <{ [24 x i8], ptr }> <{ [24 x i8] c"\00\00\00\00\00\00\00\00\08\00\00\00\00\00\00\00\08\00\00\00\00\00\00\00", ptr @"_ZN42_$LT$$RF$T$u20$as$u20$core..fmt..Debug$GT$3fmt17h00e57a321a275cfeE" }>, align 8
@alloc_4f9dfe8db7ef1972eeb96fcb1ae92451 = private unnamed_addr constant [9 x i8] c"Anthropic", align 1
@vtable.5 = private unnamed_addr constant <{ [24 x i8], ptr }> <{ [24 x i8] c"\00\00\00\00\00\00\00\00\08\00\00\00\00\00\00\00\08\00\00\00\00\00\00\00", ptr @"_ZN42_$LT$$RF$T$u20$as$u20$core..fmt..Debug$GT$3fmt17hd077c0b49957299fE" }>, align 8
@alloc_c2314664d27a3f931673074da5b6f66e = private unnamed_addr constant [15 x i8] c"NonJsonResponse", align 1
@alloc_8c9844c3a6a90a848028a03437183c9a = private unnamed_addr constant [6 x i8] c"status", align 1
@vtable.6 = private unnamed_addr constant <{ [24 x i8], ptr }> <{ [24 x i8] c"\00\00\00\00\00\00\00\00\02\00\00\00\00\00\00\00\02\00\00\00\00\00\00\00", ptr @"_ZN4core3fmt3num50_$LT$impl$u20$core..fmt..Debug$u20$for$u20$u16$GT$3fmt17h7955cd73c1ff96bdE" }>, align 8
@alloc_9bb804543209f5e9a668d8c1849e00ff = private unnamed_addr constant [4 x i8] c"body", align 1
@vtable.7 = private unnamed_addr constant <{ [24 x i8], ptr }> <{ [24 x i8] c"\00\00\00\00\00\00\00\00\08\00\00\00\00\00\00\00\08\00\00\00\00\00\00\00", ptr @"_ZN42_$LT$$RF$T$u20$as$u20$core..fmt..Debug$GT$3fmt17h036e309bbd1bec74E" }>, align 8
@alloc_4186248dfa37f30b0aa4551d6079aced = private unnamed_addr constant [18 x i8] c"UnexpectedResponse", align 1
@alloc_96af468510ea8f5f9cb1c5ccd138c101 = private unnamed_addr constant [7 x i8] c"message", align 1
@vtable.8 = private unnamed_addr constant <{ [24 x i8], ptr }> <{ [24 x i8] c"\00\00\00\00\00\00\00\00\08\00\00\00\00\00\00\00\08\00\00\00\00\00\00\00", ptr @"_ZN42_$LT$$RF$T$u20$as$u20$core..fmt..Debug$GT$3fmt17h0056c15810214fbaE" }>, align 8
@alloc_0041846db82c81f9b8ef910951b86b6f = private unnamed_addr constant [14 x i8] c"InvalidRequest", align 1
@alloc_45500aec4bb0c69d950f9beca84dd93c = private unnamed_addr constant [14 x i8] c"Authentication", align 1
@alloc_ab7ae8aa2c83156c614e7c90bf3a5bc2 = private unnamed_addr constant [7 x i8] c"Billing", align 1
@alloc_8e658b02a36b8853f273c1d5759f7875 = private unnamed_addr constant [10 x i8] c"Permission", align 1
@alloc_2201031af4f3db2ffa8285dddc089c29 = private unnamed_addr constant [8 x i8] c"NotFound", align 1
@alloc_fe96f81fcb62c98a919cec1e88b6a877 = private unnamed_addr constant [15 x i8] c"RequestTooLarge", align 1
@alloc_5313b5e80a18a1a56efbc1c873514882 = private unnamed_addr constant [9 x i8] c"RateLimit", align 1
@vtable.9 = private unnamed_addr constant <{ ptr, [16 x i8], ptr }> <{ ptr @"_ZN4core3ptr42drop_in_place$LT$alloc..string..String$GT$17hebd90fb8d5f940a3E", [16 x i8] c"\18\00\00\00\00\00\00\00\08\00\00\00\00\00\00\00", ptr @"_ZN58_$LT$alloc..string..String$u20$as$u20$core..fmt..Debug$GT$3fmt17h6bdadfc155e851afE" }>, align 8
@alloc_da9fc84f456a7be3794db92d01144896 = private unnamed_addr constant [11 x i8] c"retry_after", align 1
@vtable.a = private unnamed_addr constant <{ [24 x i8], ptr }> <{ [24 x i8] c"\00\00\00\00\00\00\00\00\08\00\00\00\00\00\00\00\08\00\00\00\00\00\00\00", ptr @"_ZN42_$LT$$RF$T$u20$as$u20$core..fmt..Debug$GT$3fmt17hb9427d2859f2466dE" }>, align 8
@alloc_101ac9f1b2ce360b71b12e4e7448d994 = private unnamed_addr constant [3 x i8] c"API", align 1
@alloc_9d2eeace429a5efc7f5121129f353534 = private unnamed_addr constant [10 x i8] c"Overloaded", align 1
@alloc_42706ad80c424b77359f062cdf071eb7 = private unnamed_addr constant [7 x i8] c"Timeout", align 1
@alloc_8cc9588efcf35543a364a34123fcfef9 = private unnamed_addr constant [7 x i8] c"Unknown", align 1
@alloc_905976595ed1b08e57e2b44a2acadea4 = private unnamed_addr constant [4 x i8] c"code", align 1
@vtable.b = private unnamed_addr constant <{ [24 x i8], ptr }> <{ [24 x i8] c"\00\00\00\00\00\00\00\00\02\00\00\00\00\00\00\00\02\00\00\00\00\00\00\00", ptr @"_ZN66_$LT$core..option..Option$LT$T$GT$$u20$as$u20$core..fmt..Debug$GT$3fmt17hbbb6cd418bb42cccE" }>, align 8
@alloc_be476ef6c975aeef42849d7343768d87 = private unnamed_addr constant [8 x i8] c"BadFirst", align 1
@vtable.c = private unnamed_addr constant <{ [24 x i8], ptr }> <{ [24 x i8] c"\00\00\00\00\00\00\00\00\08\00\00\00\00\00\00\00\08\00\00\00\00\00\00\00", ptr @"_ZN42_$LT$$RF$T$u20$as$u20$core..fmt..Debug$GT$3fmt17h4f173301853c4edbE" }>, align 8
@alloc_34e47e1681a65ce9ec811b023e78c3d8 = private unnamed_addr constant [13 x i8] c"BadTransition", align 1
@alloc_4986dd618090c125bc3e853ec5468cc0 = private unnamed_addr constant [5 x i8] c"first", align 1
@vtable.d = private unnamed_addr constant <{ ptr, [16 x i8], ptr }> <{ ptr @"_ZN4core3ptr106drop_in_place$LT$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$GT$17hb0d3b39bf406e30bE", [16 x i8] c" \00\00\00\00\00\00\00\08\00\00\00\00\00\00\00", ptr @"_ZN88_$LT$misanthropic..prompt..message..RoleMessage$LT$R$GT$$u20$as$u20$core..fmt..Debug$GT$3fmt17h834cd01f432b3e7dE" }>, align 8
@alloc_114ee15010692784d7aa12af2dd225dd = private unnamed_addr constant [6 x i8] c"second", align 1
@alloc_1d7c4d8451edc87804c9969173e3ec5f = private unnamed_addr constant [20 x i8] c"ToolResultNotLeading", align 1
@alloc_84c53b99ad03075cd02fc91e54d3a4e1 = private unnamed_addr constant [17 x i8] c"UnansweredToolUse", align 1
@alloc_067fc2ed276f3eb6967fc46f7feae7a6 = private unnamed_addr constant [10 x i8] c"unanswered", align 1
@vtable.e = private unnamed_addr constant <{ [24 x i8], ptr }> <{ [24 x i8] c"\00\00\00\00\00\00\00\00\08\00\00\00\00\00\00\00\08\00\00\00\00\00\00\00", ptr @"_ZN42_$LT$$RF$T$u20$as$u20$core..fmt..Debug$GT$3fmt17h4e4609104daf91eeE" }>, align 8
@alloc_97d92cbf2a68a6ac45a1b13da79836e4 = private unnamed_addr constant [214 x i8] c"unsafe precondition(s) violated: slice::get_unchecked requires that the index is within the slice\0A\0AThis indicates a bug in the program. This Undefined Behavior check is optional, and cannot be relied on for safety.", align 1
@alloc_920d1ade628fe08e7464cf813a42b3be = private unnamed_addr constant [16 x i8] c"InvalidKeyLength", align 1
@alloc_b31c6c8dca3d1da07e1eee656fa2f5cc = private unnamed_addr constant [6 x i8] c"actual", align 1
@vtable.f = private unnamed_addr constant <{ [24 x i8], ptr }> <{ [24 x i8] c"\00\00\00\00\00\00\00\00\08\00\00\00\00\00\00\00\08\00\00\00\00\00\00\00", ptr @"_ZN42_$LT$$RF$T$u20$as$u20$core..fmt..Debug$GT$3fmt17ha721991b0ea53568E" }>, align 8
@alloc_62f0ea6b413625199824bf4fe7be34c8 = private unnamed_addr constant <{ ptr, [16 x i8] }> <{ ptr @alloc_c86808924c6a6c540af584c966c7c14f, [16 x i8] c"u\00\00\00\00\00\00\00\9A\03\00\00\19\00\00\00" }>, align 8
@alloc_cbfdeea429b96084b620ff74647c466b = private unnamed_addr constant <{ ptr, [16 x i8] }> <{ ptr @alloc_c86808924c6a6c540af584c966c7c14f, [16 x i8] c"u\00\00\00\00\00\00\00\9A\03\00\00\0E\00\00\00" }>, align 8
@alloc_26137edaf0f0f9134544d99ec4a8facd = private unnamed_addr constant [13 x i8] c"dummy-api-key", align 1
@alloc_4771401c1b62ff9602a855ecda415c51 = private unnamed_addr constant [10 x i8] c"src\\lib.rs", align 1
@alloc_46404ed8a5ab13dcd083589d2953351c = private unnamed_addr constant <{ ptr, [16 x i8] }> <{ ptr @alloc_4771401c1b62ff9602a855ecda415c51, [16 x i8] c"\0A\00\00\00\00\00\00\00\19\00\00\00;\00\00\00" }>, align 8
@alloc_da36a57fa65e0eec20bd7786fa7b529a = private unnamed_addr constant <{ ptr, [16 x i8] }> <{ ptr @alloc_4771401c1b62ff9602a855ecda415c51, [16 x i8] c"\0A\00\00\00\00\00\00\00\1D\00\00\00\0A\00\00\00" }>, align 8
@alloc_81fc3fdfb101020df5f12e76aae3afaa = private unnamed_addr constant <{ ptr, [16 x i8] }> <{ ptr @alloc_4771401c1b62ff9602a855ecda415c51, [16 x i8] c"\0A\00\00\00\00\00\00\00\18\00\00\00Q\00\00\00" }>, align 8
@alloc_89f2983d41b497819b93f33ed401a022 = private unnamed_addr constant <{ ptr, [16 x i8] }> <{ ptr @alloc_4771401c1b62ff9602a855ecda415c51, [16 x i8] c"\0A\00\00\00\00\00\00\00\1F\00\00\00#\00\00\00" }>, align 8
@alloc_9e6a6168768470af30921519e13425a0 = private unnamed_addr constant <{ ptr, [16 x i8] }> <{ ptr @alloc_4771401c1b62ff9602a855ecda415c51, [16 x i8] c"\0A\00\00\00\00\00\00\00#\00\00\00;\00\00\00" }>, align 8
@alloc_5489c671b0b9b196c6445d24bdfea32b = private unnamed_addr constant <{ ptr, [16 x i8] }> <{ ptr @alloc_4771401c1b62ff9602a855ecda415c51, [16 x i8] c"\0A\00\00\00\00\00\00\00'\00\00\00\0A\00\00\00" }>, align 8
@alloc_6c9841a87da6571edecc93494eee6a2c = private unnamed_addr constant <{ ptr, [16 x i8] }> <{ ptr @alloc_4771401c1b62ff9602a855ecda415c51, [16 x i8] c"\0A\00\00\00\00\00\00\00\22\00\00\00H\00\00\00" }>, align 8
@alloc_977023cf9969551de5b678c700ff8a31 = private unnamed_addr constant <{ ptr, [16 x i8] }> <{ ptr @alloc_4771401c1b62ff9602a855ecda415c51, [16 x i8] c"\0A\00\00\00\00\00\00\00)\00\00\00\22\00\00\00" }>, align 8

; <core::array::iter::iter_inner::PolymorphicIter<DATA> as core::ops::drop::Drop>::drop
; Function Attrs: inlinehint uwtable
define void @"_ZN100_$LT$core..array..iter..iter_inner..PolymorphicIter$LT$DATA$GT$$u20$as$u20$core..ops..drop..Drop$GT$4drop17he94e64ad313a7e26E"(ptr align 8 %self) unnamed_addr #0 {
start:
  %_2 = getelementptr inbounds i8, ptr %self, i64 16
  %_3.0 = load i64, ptr %self, align 8
  %0 = getelementptr inbounds i8, ptr %self, i64 8
  %_3.1 = load i64, ptr %0, align 8
; call <[core::mem::maybe_uninit::MaybeUninit<T>; N] as core::array::iter::iter_inner::PartialDrop>::partial_drop
  call void @"_ZN129_$LT$$u5b$core..mem..maybe_uninit..MaybeUninit$LT$T$GT$$u3b$$u20$N$u5d$$u20$as$u20$core..array..iter..iter_inner..PartialDrop$GT$12partial_drop17h4411051c7149c04aE"(ptr align 8 %_2, i64 %_3.0, i64 %_3.1)
  ret void
}

; <core::iter::adapters::map::Map<I,F> as core::iter::traits::iterator::Iterator>::fold
; Function Attrs: uwtable
define void @"_ZN102_$LT$core..iter..adapters..map..Map$LT$I$C$F$GT$$u20$as$u20$core..iter..traits..iterator..Iterator$GT$4fold17hd8747bbf6b8dbf20E"(ptr align 8 %self, ptr align 8 %g) unnamed_addr #1 {
start:
  %_5 = alloca [24 x i8], align 8
  %_4 = alloca [40 x i8], align 8
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_4, ptr align 8 %self, i64 40, i1 false)
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_5, ptr align 8 %g, i64 24, i1 false)
; call <core::array::iter::IntoIter<T,_> as core::iter::traits::iterator::Iterator>::fold
  call void @"_ZN99_$LT$core..array..iter..IntoIter$LT$T$C$_$GT$$u20$as$u20$core..iter..traits..iterator..Iterator$GT$4fold17h81e0f82241a328aaE"(ptr align 8 %_4, ptr align 8 %_5)
  ret void
}

; <core::iter::adapters::map::Map<I,F> as core::iter::traits::iterator::Iterator>::size_hint
; Function Attrs: inlinehint uwtable
define void @"_ZN102_$LT$core..iter..adapters..map..Map$LT$I$C$F$GT$$u20$as$u20$core..iter..traits..iterator..Iterator$GT$9size_hint17h66acc32d3e0bbd05E"(ptr sret([24 x i8]) align 8 %_0, ptr align 8 %self) unnamed_addr #0 {
start:
; call <core::array::iter::IntoIter<T,_> as core::iter::traits::iterator::Iterator>::size_hint
  call void @"_ZN99_$LT$core..array..iter..IntoIter$LT$T$C$_$GT$$u20$as$u20$core..iter..traits..iterator..Iterator$GT$9size_hint17h8b8ff9d275ad0b93E"(ptr sret([24 x i8]) align 8 %_0, ptr align 8 %self)
  ret void
}

; <core::ops::index_range::IndexRange as core::slice::index::SliceIndex<[T]>>::get_unchecked_mut::precondition_check
; Function Attrs: inlinehint nounwind uwtable
define hidden void @"_ZN104_$LT$core..ops..index_range..IndexRange$u20$as$u20$core..slice..index..SliceIndex$LT$$u5b$T$u5d$$GT$$GT$17get_unchecked_mut18precondition_check17hb66bbae7eb789ee9E"(i64 %end, i64 %len) unnamed_addr #2 {
start:
  %_3 = icmp ule i64 %end, %len
  br i1 %_3, label %bb1, label %bb2

bb2:                                              ; preds = %start
; call core::panicking::panic_nounwind
  call void @_ZN4core9panicking14panic_nounwind17hb115782c8cb05dd0E(ptr align 1 @alloc_5a8fdd84b3281310cbf6b74bb6bf0065, i64 218) #15
  unreachable

bb1:                                              ; preds = %start
  ret void
}

; <alloc::vec::Vec<T> as alloc::vec::spec_from_iter_nested::SpecFromIterNested<T,I>>::from_iter
; Function Attrs: uwtable
define void @"_ZN111_$LT$alloc..vec..Vec$LT$T$GT$$u20$as$u20$alloc..vec..spec_from_iter_nested..SpecFromIterNested$LT$T$C$I$GT$$GT$9from_iter17h549752c212276cbaE"(ptr sret([24 x i8]) align 8 %_0, ptr align 8 %iterator, ptr align 8 %0) unnamed_addr #1 personality ptr @__CxxFrameHandler3 {
start:
  %_12 = alloca [1 x i8], align 1
  %_11 = alloca [40 x i8], align 8
  %_8 = alloca [48 x i8], align 8
  %_3 = alloca [24 x i8], align 8
  %vector = alloca [24 x i8], align 8
  store i8 1, ptr %_12, align 1
; invoke <core::iter::adapters::map::Map<I,F> as core::iter::traits::iterator::Iterator>::size_hint
  invoke void @"_ZN102_$LT$core..iter..adapters..map..Map$LT$I$C$F$GT$$u20$as$u20$core..iter..traits..iterator..Iterator$GT$9size_hint17h66acc32d3e0bbd05E"(ptr sret([24 x i8]) align 8 %_3, ptr align 8 %iterator)
          to label %bb1 unwind label %funclet_bb8

bb8:                                              ; preds = %funclet_bb8
  %1 = load i8, ptr %_12, align 1
  %2 = trunc nuw i8 %1 to i1
  br i1 %2, label %bb7, label %bb6

funclet_bb8:                                      ; preds = %bb2, %bb5, %bb3, %start
  %cleanuppad = cleanuppad within none []
  br label %bb8

bb1:                                              ; preds = %start
  %3 = getelementptr inbounds i8, ptr %_3, i64 8
  %_5 = load i64, ptr %3, align 8
  %4 = getelementptr inbounds i8, ptr %3, i64 8
  %5 = load i64, ptr %4, align 8
  %6 = trunc nuw i64 %_5 to i1
  br i1 %6, label %bb3, label %bb2

bb3:                                              ; preds = %bb1
  %7 = getelementptr inbounds i8, ptr %_3, i64 8
  %8 = getelementptr inbounds i8, ptr %7, i64 8
  %upper = load i64, ptr %8, align 8
; invoke alloc::raw_vec::RawVecInner<A>::with_capacity_in
  %9 = invoke { i64, ptr } @"_ZN5alloc7raw_vec20RawVecInner$LT$A$GT$16with_capacity_in17h25686f63b1e1ebd8E"(i64 %upper, i64 8, i64 32, ptr align 8 %0)
          to label %bb9 unwind label %funclet_bb8

bb2:                                              ; preds = %bb1
  store ptr @alloc_11d257f5ed6cc7fc38feaa801053bac6, ptr %_8, align 8
  %10 = getelementptr inbounds i8, ptr %_8, i64 8
  store i64 1, ptr %10, align 8
  %11 = load ptr, ptr @anon.9bb7cee0307838987e4b4b15e8b33297.0, align 8
  %12 = load i64, ptr getelementptr inbounds (i8, ptr @anon.9bb7cee0307838987e4b4b15e8b33297.0, i64 8), align 8
  %13 = getelementptr inbounds i8, ptr %_8, i64 32
  store ptr %11, ptr %13, align 8
  %14 = getelementptr inbounds i8, ptr %13, i64 8
  store i64 %12, ptr %14, align 8
  %15 = getelementptr inbounds i8, ptr %_8, i64 16
  store ptr inttoptr (i64 8 to ptr), ptr %15, align 8
  %16 = getelementptr inbounds i8, ptr %15, i64 8
  store i64 0, ptr %16, align 8
; invoke core::panicking::panic_fmt
  invoke void @_ZN4core9panicking9panic_fmt17h6b7e0a7dad869f5aE(ptr align 8 %_8, ptr align 8 %0) #16
          to label %unreachable unwind label %funclet_bb8

bb9:                                              ; preds = %bb3
  %_16.0 = extractvalue { i64, ptr } %9, 0
  %_16.1 = extractvalue { i64, ptr } %9, 1
  store i64 %_16.0, ptr %vector, align 8
  %17 = getelementptr inbounds i8, ptr %vector, i64 8
  store ptr %_16.1, ptr %17, align 8
  %18 = getelementptr inbounds i8, ptr %vector, i64 16
  store i64 0, ptr %18, align 8
  store i8 0, ptr %_12, align 1
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_11, ptr align 8 %iterator, i64 40, i1 false)
; invoke <alloc::vec::Vec<T,A> as alloc::vec::spec_extend::SpecExtend<T,I>>::spec_extend
  invoke void @"_ZN97_$LT$alloc..vec..Vec$LT$T$C$A$GT$$u20$as$u20$alloc..vec..spec_extend..SpecExtend$LT$T$C$I$GT$$GT$11spec_extend17h3668163d5ed909c3E"(ptr align 8 %vector, ptr align 8 %_11, ptr align 8 %0)
          to label %bb4 unwind label %funclet_bb5

bb5:                                              ; preds = %funclet_bb5
; call core::ptr::drop_in_place<alloc::vec::Vec<misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>>>
  call void @"_ZN4core3ptr129drop_in_place$LT$alloc..vec..Vec$LT$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$GT$$GT$17h80beb9192a52b8e4E"(ptr align 8 %vector) #17 [ "funclet"(token %cleanuppad1) ]
  cleanupret from %cleanuppad1 unwind label %funclet_bb8

funclet_bb5:                                      ; preds = %bb9
  %cleanuppad1 = cleanuppad within none []
  br label %bb5

bb4:                                              ; preds = %bb9
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_0, ptr align 8 %vector, i64 24, i1 false)
  ret void

unreachable:                                      ; preds = %bb2
  unreachable

bb10:                                             ; No predecessors!
  unreachable

bb6:                                              ; preds = %bb7, %bb8
  cleanupret from %cleanuppad unwind to caller

bb7:                                              ; preds = %bb8
; call core::ptr::drop_in_place<core::iter::adapters::map::Map<core::array::iter::IntoIter<(misanthropic::prompt::message::Role,&str),1_usize>,<(misanthropic::prompt::message::Role,&str) as core::convert::Into<misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>>>::into>>
  call void @"_ZN4core3ptr351drop_in_place$LT$core..iter..adapters..map..Map$LT$core..array..iter..IntoIter$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$C$1_usize$GT$$C$$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$u20$as$u20$core..convert..Into$LT$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$GT$$GT$..into$GT$$GT$17h290ac583dfbf459aE"(ptr align 8 %iterator) #17 [ "funclet"(token %cleanuppad) ]
  br label %bb6
}

; <[core::mem::maybe_uninit::MaybeUninit<T>] as core::array::iter::iter_inner::PartialDrop>::partial_drop
; Function Attrs: uwtable
define void @"_ZN118_$LT$$u5b$core..mem..maybe_uninit..MaybeUninit$LT$T$GT$$u5d$$u20$as$u20$core..array..iter..iter_inner..PartialDrop$GT$12partial_drop17hd5e8bd09f3f183cbE"(ptr align 8 %self.0, i64 %self.1, i64 %alive.0, i64 %alive.1) unnamed_addr #1 {
start:
  %index = alloca [16 x i8], align 8
  store i64 %alive.0, ptr %index, align 8
  %0 = getelementptr inbounds i8, ptr %index, i64 8
  store i64 %alive.1, ptr %0, align 8
  br label %bb1

bb1:                                              ; preds = %start
; call <core::ops::index_range::IndexRange as core::slice::index::SliceIndex<[T]>>::get_unchecked_mut::precondition_check
  call void @"_ZN104_$LT$core..ops..index_range..IndexRange$u20$as$u20$core..slice..index..SliceIndex$LT$$u5b$T$u5d$$GT$$GT$17get_unchecked_mut18precondition_check17hb66bbae7eb789ee9E"(i64 %alive.1, i64 %self.1) #18
  br label %bb3

bb3:                                              ; preds = %bb1
  %len = sub nuw i64 %alive.1, %alive.0
  %_17 = getelementptr inbounds nuw %"core::mem::maybe_uninit::MaybeUninit<(misanthropic::prompt::message::Role, &str)>", ptr %self.0, i64 %alive.0
  %1 = icmp eq i64 %len, 0
  br i1 %1, label %bb4, label %bb5

bb4:                                              ; preds = %bb5, %bb3
  ret void

bb5:                                              ; preds = %bb3
  br label %bb4
}

; <[core::mem::maybe_uninit::MaybeUninit<T>; N] as core::array::iter::iter_inner::PartialDrop>::partial_drop
; Function Attrs: uwtable
define void @"_ZN129_$LT$$u5b$core..mem..maybe_uninit..MaybeUninit$LT$T$GT$$u3b$$u20$N$u5d$$u20$as$u20$core..array..iter..iter_inner..PartialDrop$GT$12partial_drop17h4411051c7149c04aE"(ptr align 8 %self, i64 %alive.0, i64 %alive.1) unnamed_addr #1 {
start:
; call <[core::mem::maybe_uninit::MaybeUninit<T>] as core::array::iter::iter_inner::PartialDrop>::partial_drop
  call void @"_ZN118_$LT$$u5b$core..mem..maybe_uninit..MaybeUninit$LT$T$GT$$u5d$$u20$as$u20$core..array..iter..iter_inner..PartialDrop$GT$12partial_drop17hd5e8bd09f3f183cbE"(ptr align 8 %self, i64 1, i64 %alive.0, i64 %alive.1)
  ret void
}

; misanthropic::client::Client::new
; Function Attrs: uwtable
define void @_ZN12misanthropic6client6Client3new17h20d5e4a77330790fE(ptr sret([56 x i8]) align 8 %_0, ptr align 8 %key) unnamed_addr #1 {
start:
  %val = alloca [108 x i8], align 1
  %_4 = alloca [112 x i8], align 8
  %_3 = alloca [112 x i8], align 8
  %_2 = alloca [56 x i8], align 8
; call <T as core::convert::TryInto<U>>::try_into
  call void @"_ZN53_$LT$T$u20$as$u20$core..convert..TryInto$LT$U$GT$$GT$8try_into17hb9d123282d886cc6E"(ptr sret([112 x i8]) align 8 %_4, ptr align 8 %key)
; call <core::result::Result<T,E> as core::ops::try_trait::Try>::branch
  call void @"_ZN79_$LT$core..result..Result$LT$T$C$E$GT$$u20$as$u20$core..ops..try_trait..Try$GT$6branch17h434501de076f7e7bE"(ptr sret([112 x i8]) align 8 %_3, ptr align 8 %_4)
  %0 = load i8, ptr %_3, align 8
  %1 = trunc nuw i8 %0 to i1
  %_5 = zext i1 %1 to i64
  %2 = trunc nuw i64 %_5 to i1
  br i1 %2, label %bb5, label %bb4

bb5:                                              ; preds = %start
  %3 = getelementptr inbounds i8, ptr %_3, i64 8
  %residual = load i64, ptr %3, align 8
; call <core::result::Result<T,F> as core::ops::try_trait::FromResidual<core::result::Result<core::convert::Infallible,E>>>::from_residual
  call void @"_ZN153_$LT$core..result..Result$LT$T$C$F$GT$$u20$as$u20$core..ops..try_trait..FromResidual$LT$core..result..Result$LT$core..convert..Infallible$C$E$GT$$GT$$GT$13from_residual17h748ff2f7f3335997E"(ptr sret([56 x i8]) align 8 %_0, i64 %residual, ptr align 8 @alloc_cb949ee21930fa9ac27f98d4a4eed7ed)
  br label %bb7

bb4:                                              ; preds = %start
  %4 = getelementptr inbounds i8, ptr %_3, i64 1
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %val, ptr align 1 %4, i64 108, i1 false)
; call misanthropic::client::Client::from_key
  call void @_ZN12misanthropic6client6Client8from_key17he2bb25b445202670E(ptr sret([56 x i8]) align 8 %_2, ptr align 1 %val)
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_0, ptr align 8 %_2, i64 56, i1 false)
  br label %bb7

bb7:                                              ; preds = %bb5, %bb4
  ret void

bb3:                                              ; No predecessors!
  unreachable
}

; misanthropic::client::Client::stream
; Function Attrs: uwtable
define void @_ZN12misanthropic6client6Client6stream17ha46a03e894362e7cE(ptr sret([1192 x i8]) align 8 %_0, ptr align 8 %self, ptr align 8 %prompt) unnamed_addr #1 {
start:
  %0 = getelementptr inbounds i8, ptr %_0, i64 1168
  store ptr %self, ptr %0, align 8
  %1 = getelementptr inbounds i8, ptr %_0, i64 1176
  store ptr %prompt, ptr %1, align 8
  %2 = getelementptr inbounds i8, ptr %_0, i64 1185
  store i8 0, ptr %2, align 1
  ret void
}

; misanthropic::client::Client::stream::{{closure}}
; Function Attrs: inlinehint uwtable
define void @"_ZN12misanthropic6client6Client6stream28_$u7b$$u7b$closure$u7d$$u7d$17h14a7c3bdf53f5a4cE"(ptr sret([360 x i8]) align 8 %_0, ptr align 8 %0, ptr align 8 %_2) unnamed_addr #0 personality ptr @__CxxFrameHandler3 {
start:
  %_task_context = alloca [8 x i8], align 8
  %_32 = alloca [360 x i8], align 8
  %_30 = alloca [1 x i8], align 1
  %_29 = alloca [48 x i8], align 8
  %stream = alloca [360 x i8], align 8
  %val1 = alloca [360 x i8], align 8
  %residual = alloca [48 x i8], align 8
  %result = alloca [360 x i8], align 8
  %_18 = alloca [360 x i8], align 8
  %_17 = alloca [72 x i8], align 8
  %_16 = alloca [1096 x i8], align 8
  %_15 = alloca [1096 x i8], align 8
  %_14 = alloca [360 x i8], align 8
  %_13 = alloca [360 x i8], align 8
  %_10 = alloca [72 x i8], align 8
  %val = alloca [72 x i8], align 8
  %_6 = alloca [72 x i8], align 8
  %_5 = alloca [72 x i8], align 8
  %_1 = alloca [8 x i8], align 8
  store ptr %0, ptr %_1, align 8
  %_35 = load ptr, ptr %_1, align 8
  %1 = getelementptr inbounds i8, ptr %_35, i64 1185
  %2 = load i8, ptr %1, align 1
  %_34 = zext i8 %2 to i32
  switch i32 %_34, label %bb4 [
    i32 0, label %bb1
    i32 1, label %bb37
    i32 2, label %bb36
    i32 3, label %bb35
  ]

bb4:                                              ; preds = %start
  unreachable

bb1:                                              ; preds = %start
  store ptr %_2, ptr %_task_context, align 8
  %_36 = load ptr, ptr %_1, align 8
  %3 = getelementptr inbounds i8, ptr %_36, i64 1184
  store i8 0, ptr %3, align 8
  store i8 0, ptr %_30, align 1
  %_37 = load ptr, ptr %_1, align 8
  %4 = getelementptr inbounds i8, ptr %_37, i64 1168
  %self = load ptr, ptr %4, align 8
  %_38 = load ptr, ptr %_1, align 8
  %5 = getelementptr inbounds i8, ptr %_38, i64 1176
  %prompt = load ptr, ptr %5, align 8
; invoke serde_json::value::to_value
  invoke void @_ZN10serde_json5value8to_value17h9da1b1abed4c459aE(ptr sret([72 x i8]) align 8 %_6, ptr align 8 %prompt)
          to label %bb2 unwind label %funclet_bb28

bb37:                                             ; preds = %bb37, %start
  br i1 false, label %bb37, label %panic

bb36:                                             ; preds = %bb36, %start
  br i1 false, label %bb36, label %panic6

bb35:                                             ; preds = %start
  store ptr %_2, ptr %_task_context, align 8
  br label %bb12

bb28:                                             ; preds = %funclet_bb28
  %_52 = load ptr, ptr %_1, align 8
  %6 = getelementptr inbounds i8, ptr %_52, i64 1184
  store i8 0, ptr %6, align 8
  %_55 = load ptr, ptr %_1, align 8
  %7 = getelementptr inbounds i8, ptr %_55, i64 1185
  store i8 2, ptr %7, align 1
  cleanupret from %cleanuppad unwind to caller

funclet_bb28:                                     ; preds = %bb33, %bb34_cleanup_trampoline_bb28, %bb6, %bb2, %bb1
  %cleanuppad = cleanuppad within none []
  br label %bb28

bb2:                                              ; preds = %bb1
; invoke <core::result::Result<T,E> as core::ops::try_trait::Try>::branch
  invoke void @"_ZN79_$LT$core..result..Result$LT$T$C$E$GT$$u20$as$u20$core..ops..try_trait..Try$GT$6branch17h583b51c8ebd1bc09E"(ptr sret([72 x i8]) align 8 %_5, ptr align 8 %_6)
          to label %bb3 unwind label %funclet_bb28

bb3:                                              ; preds = %bb2
  %8 = load i64, ptr %_5, align 8
  %9 = icmp eq i64 %8, -9223372036854775803
  %_7 = select i1 %9, i64 1, i64 0
  %10 = trunc nuw i64 %_7 to i1
  br i1 %10, label %bb6, label %bb5

bb6:                                              ; preds = %bb3
  %11 = getelementptr inbounds i8, ptr %_5, i64 8
  %residual5 = load ptr, ptr %11, align 8
; invoke <core::result::Result<T,F> as core::ops::try_trait::FromResidual<core::result::Result<core::convert::Infallible,E>>>::from_residual
  invoke void @"_ZN153_$LT$core..result..Result$LT$T$C$F$GT$$u20$as$u20$core..ops..try_trait..FromResidual$LT$core..result..Result$LT$core..convert..Infallible$C$E$GT$$GT$$GT$13from_residual17h60913bf8c2b68006E"(ptr sret([360 x i8]) align 8 %_32, ptr align 8 %residual5, ptr align 8 @alloc_56e9bd399e30d3413bf7eef70d31cd4b)
          to label %bb38 unwind label %funclet_bb28

bb5:                                              ; preds = %bb3
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %val, ptr align 8 %_5, i64 72, i1 false)
  %_39 = load ptr, ptr %_1, align 8
  %12 = getelementptr inbounds i8, ptr %_39, i64 1184
  store i8 1, ptr %12, align 8
  %_40 = load ptr, ptr %_1, align 8
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_40, ptr align 8 %val, i64 72, i1 false)
  store i8 1, ptr %_30, align 1
  %13 = getelementptr inbounds i8, ptr %_10, i64 8
  store i8 1, ptr %13, align 8
  store i64 -9223372036854775807, ptr %_10, align 8
  %_41 = load ptr, ptr %_1, align 8
; invoke serde_json::value::index::<impl core::ops::index::IndexMut<I> for serde_json::value::Value>::index_mut
  %_11 = invoke align 8 ptr @"_ZN10serde_json5value5index90_$LT$impl$u20$core..ops..index..IndexMut$LT$I$GT$$u20$for$u20$serde_json..value..Value$GT$9index_mut17h714324fb407ccd14E"(ptr align 8 %_41, ptr align 1 @alloc_16157024dd92dd2dc2624dbf6332a09b, i64 6, ptr align 8 @alloc_a442c2025036816d4885b50e4d2c7d48)
          to label %bb7 unwind label %funclet_bb32

bb32:                                             ; preds = %funclet_bb32
  %14 = load i8, ptr %_30, align 1
  %15 = trunc nuw i8 %14 to i1
  br i1 %15, label %bb31, label %bb27

funclet_bb32:                                     ; preds = %bb9, %bb5
  %cleanuppad2 = cleanuppad within none []
  br label %bb32

bb7:                                              ; preds = %bb5
; invoke core::ptr::drop_in_place<serde_json::value::Value>
  invoke void @"_ZN4core3ptr45drop_in_place$LT$serde_json..value..Value$GT$17h3b0bd242f80d52afE"(ptr align 8 %_11)
          to label %bb8 unwind label %funclet_bb9

bb9:                                              ; preds = %funclet_bb9
  store i8 0, ptr %_30, align 1
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_11, ptr align 8 %_10, i64 72, i1 false)
  cleanupret from %cleanuppad3 unwind label %funclet_bb32

funclet_bb9:                                      ; preds = %bb7
  %cleanuppad3 = cleanuppad within none []
  br label %bb9

bb8:                                              ; preds = %bb7
  store i8 0, ptr %_30, align 1
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_11, ptr align 8 %_10, i64 72, i1 false)
  store i8 0, ptr %_30, align 1
  %_42 = load ptr, ptr %_1, align 8
  %16 = getelementptr inbounds i8, ptr %_42, i64 1184
  store i8 0, ptr %16, align 8
  %_43 = load ptr, ptr %_1, align 8
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_17, ptr align 8 %_43, i64 72, i1 false)
; invoke misanthropic::client::Client::request
  invoke void @_ZN12misanthropic6client6Client7request17hbb050df3dac178b5E(ptr sret([1096 x i8]) align 8 %_16, ptr align 8 %self, ptr align 8 %_17)
          to label %bb10 unwind label %funclet_bb34

bb34:                                             ; preds = %funclet_bb34
  %_54 = load ptr, ptr %_1, align 8
  %17 = getelementptr inbounds i8, ptr %_54, i64 1184
  %18 = load i8, ptr %17, align 8
  %19 = trunc nuw i8 %18 to i1
  br i1 %19, label %bb33, label %bb34_cleanup_trampoline_bb28

funclet_bb34:                                     ; preds = %bb26, %bb20, %bb21, %bb30, %bb17, %bb16, %bb27, %bb10, %bb8
  %cleanuppad4 = cleanuppad within none []
  br label %bb34

bb10:                                             ; preds = %bb8
; invoke <F as core::future::into_future::IntoFuture>::into_future
  invoke void @"_ZN59_$LT$F$u20$as$u20$core..future..into_future..IntoFuture$GT$11into_future17hf9d1281ba75964f2E"(ptr sret([1096 x i8]) align 8 %_15, ptr align 8 %_16)
          to label %bb11 unwind label %funclet_bb34

bb11:                                             ; preds = %bb10
  %_44 = load ptr, ptr %_1, align 8
  %20 = getelementptr inbounds i8, ptr %_44, i64 72
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %20, ptr align 8 %_15, i64 1096, i1 false)
  br label %bb12

bb12:                                             ; preds = %bb35, %bb11
  %_45 = load ptr, ptr %_1, align 8
  %_20 = getelementptr inbounds i8, ptr %_45, i64 72
  br label %bb13

bb27:                                             ; preds = %bb31, %bb32
  store i8 0, ptr %_30, align 1
  cleanupret from %cleanuppad2 unwind label %funclet_bb34

bb31:                                             ; preds = %bb32
; call core::ptr::drop_in_place<serde_json::value::Value>
  call void @"_ZN4core3ptr45drop_in_place$LT$serde_json..value..Value$GT$17h3b0bd242f80d52afE"(ptr align 8 %_10) #17 [ "funclet"(token %cleanuppad2) ]
  br label %bb27

bb38:                                             ; preds = %bb6
  br label %bb24

bb24:                                             ; preds = %bb39, %bb38
  %_49 = load ptr, ptr %_1, align 8
  %21 = getelementptr inbounds i8, ptr %_49, i64 1184
  store i8 0, ptr %21, align 8
  br label %bb25

panic:                                            ; preds = %bb37
; call core::panicking::panic_const::panic_const_async_fn_resumed
  call void @_ZN4core9panicking11panic_const28panic_const_async_fn_resumed17hf968b268d09f757eE(ptr align 8 @alloc_9ff19f39cc9b55a493c0422322b7f3f4) #16
  unreachable

panic6:                                           ; preds = %bb36
; call core::panicking::panic_const::panic_const_async_fn_resumed_panic
  call void @_ZN4core9panicking11panic_const34panic_const_async_fn_resumed_panic17h3200919381e4fb33E(ptr align 8 @alloc_9ff19f39cc9b55a493c0422322b7f3f4) #16
  unreachable

bb26:                                             ; preds = %funclet_bb26
  %_51 = load ptr, ptr %_1, align 8
  %22 = getelementptr inbounds i8, ptr %_51, i64 72
; call core::ptr::drop_in_place<misanthropic::client::Client::request<serde_json::value::Value>::{{closure}}>
  call void @"_ZN4core3ptr119drop_in_place$LT$misanthropic..client..Client..request$LT$serde_json..value..Value$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$17h3f71628b587fadc0E"(ptr align 8 %22) #17 [ "funclet"(token %cleanuppad7) ]
  cleanupret from %cleanuppad7 unwind label %funclet_bb34

funclet_bb26:                                     ; preds = %bb13
  %cleanuppad7 = cleanuppad within none []
  br label %bb26

bb13:                                             ; preds = %bb12
  %_21 = load ptr, ptr %_task_context, align 8
; invoke misanthropic::client::Client::request::{{closure}}
  invoke void @"_ZN12misanthropic6client6Client7request28_$u7b$$u7b$closure$u7d$$u7d$17h0a8458d8f61a91e7E"(ptr sret([360 x i8]) align 8 %_18, ptr align 8 %_20, ptr align 8 %_21)
          to label %bb14 unwind label %funclet_bb26

bb14:                                             ; preds = %bb13
  %23 = load i64, ptr %_18, align 8
  %24 = icmp eq i64 %23, 20
  %_22 = select i1 %24, i64 1, i64 0
  %25 = trunc nuw i64 %_22 to i1
  br i1 %25, label %bb15, label %bb16

bb15:                                             ; preds = %bb14
  store i64 19, ptr %_0, align 8
  %_46 = load ptr, ptr %_1, align 8
  %26 = getelementptr inbounds i8, ptr %_46, i64 1185
  store i8 3, ptr %26, align 1
  ret void

bb16:                                             ; preds = %bb14
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %result, ptr align 8 %_18, i64 360, i1 false)
  %_47 = load ptr, ptr %_1, align 8
  %27 = getelementptr inbounds i8, ptr %_47, i64 72
; invoke core::ptr::drop_in_place<misanthropic::client::Client::request<serde_json::value::Value>::{{closure}}>
  invoke void @"_ZN4core3ptr119drop_in_place$LT$misanthropic..client..Client..request$LT$serde_json..value..Value$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$17h3f71628b587fadc0E"(ptr align 8 %27)
          to label %bb17 unwind label %funclet_bb34

bb17:                                             ; preds = %bb16
; invoke <core::result::Result<T,E> as core::ops::try_trait::Try>::branch
  invoke void @"_ZN79_$LT$core..result..Result$LT$T$C$E$GT$$u20$as$u20$core..ops..try_trait..Try$GT$6branch17h2b8a3335c0e4df38E"(ptr sret([360 x i8]) align 8 %_14, ptr align 8 %result)
          to label %bb18 unwind label %funclet_bb34

bb18:                                             ; preds = %bb17
  %28 = load i64, ptr %_14, align 8
  %29 = icmp eq i64 %28, 19
  %_24 = select i1 %29, i64 1, i64 0
  %30 = trunc nuw i64 %_24 to i1
  br i1 %30, label %bb20, label %bb19

bb20:                                             ; preds = %bb18
  %31 = getelementptr inbounds i8, ptr %_14, i64 8
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %residual, ptr align 8 %31, i64 48, i1 false)
; invoke <core::result::Result<T,F> as core::ops::try_trait::FromResidual<core::result::Result<core::convert::Infallible,E>>>::from_residual
  invoke void @"_ZN153_$LT$core..result..Result$LT$T$C$F$GT$$u20$as$u20$core..ops..try_trait..FromResidual$LT$core..result..Result$LT$core..convert..Infallible$C$E$GT$$GT$$GT$13from_residual17h33c183a3cd5d690bE"(ptr sret([360 x i8]) align 8 %_32, ptr align 8 %residual, ptr align 8 @alloc_97a13f3d19b3fa2879ca5b761b6eb98d)
          to label %bb39 unwind label %funclet_bb34

bb19:                                             ; preds = %bb18
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %val1, ptr align 8 %_14, i64 360, i1 false)
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_13, ptr align 8 %val1, i64 360, i1 false)
  %32 = load i64, ptr %_13, align 8
  %33 = icmp eq i64 %32, 18
  %_27 = select i1 %33, i64 0, i64 1
  %34 = trunc nuw i64 %_27 to i1
  br i1 %34, label %bb22, label %bb21

bb22:                                             ; preds = %bb19
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %stream, ptr align 8 %_13, i64 360, i1 false)
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_32, ptr align 8 %stream, i64 360, i1 false)
  %35 = load i64, ptr %_13, align 8
  %36 = icmp eq i64 %35, 18
  %_31 = select i1 %36, i64 0, i64 1
  %37 = trunc nuw i64 %_31 to i1
  br i1 %37, label %bb23, label %bb30

bb21:                                             ; preds = %bb19
; invoke core::ptr::drop_in_place<misanthropic::response::Response>
  invoke void @"_ZN4core3ptr53drop_in_place$LT$misanthropic..response..Response$GT$17h91fab948d54fcbb3E"(ptr align 8 %_13)
          to label %bb29 unwind label %funclet_bb34

bb23:                                             ; preds = %bb29, %bb30, %bb22
  %_48 = load ptr, ptr %_1, align 8
  %38 = getelementptr inbounds i8, ptr %_48, i64 1184
  store i8 0, ptr %38, align 8
  br label %bb25

bb30:                                             ; preds = %bb22
; invoke core::ptr::drop_in_place<misanthropic::response::Response>
  invoke void @"_ZN4core3ptr53drop_in_place$LT$misanthropic..response..Response$GT$17h91fab948d54fcbb3E"(ptr align 8 %_13)
          to label %bb23 unwind label %funclet_bb34

bb29:                                             ; preds = %bb21
  %39 = getelementptr inbounds i8, ptr %_29, i64 8
  store ptr @alloc_8add1a43e0a2ee2ff94337595fe8e6b5, ptr %39, align 8
  %40 = getelementptr inbounds i8, ptr %39, i64 8
  store i64 33, ptr %40, align 8
  store i16 15, ptr %_29, align 8
  %41 = getelementptr inbounds i8, ptr %_32, i64 8
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %41, ptr align 8 %_29, i64 48, i1 false)
  store i64 18, ptr %_32, align 8
  br label %bb23

bb25:                                             ; preds = %bb24, %bb23
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_0, ptr align 8 %_32, i64 360, i1 false)
  %_50 = load ptr, ptr %_1, align 8
  %42 = getelementptr inbounds i8, ptr %_50, i64 1185
  store i8 1, ptr %42, align 1
  ret void

bb39:                                             ; preds = %bb20
  br label %bb24

bb34_cleanup_trampoline_bb28:                     ; preds = %bb34
  cleanupret from %cleanuppad4 unwind label %funclet_bb28

bb33:                                             ; preds = %bb34
  %_53 = load ptr, ptr %_1, align 8
; call core::ptr::drop_in_place<serde_json::value::Value>
  call void @"_ZN4core3ptr45drop_in_place$LT$serde_json..value..Value$GT$17h3b0bd242f80d52afE"(ptr align 8 %_53) #17 [ "funclet"(token %cleanuppad4) ]
  cleanupret from %cleanuppad4 unwind label %funclet_bb28
}

; misanthropic::prompt::Prompt::messages
; Function Attrs: uwtable
define void @_ZN12misanthropic6prompt6Prompt8messages17h4799d00569ae1beeE(ptr sret([384 x i8]) align 8 %_0, ptr align 8 %self, ptr align 8 %messages) unnamed_addr #1 personality ptr @__CxxFrameHandler3 {
start:
  %_11 = alloca [384 x i8], align 8
  %residual = alloca [64 x i8], align 8
  %_7 = alloca [64 x i8], align 8
  %_6 = alloca [64 x i8], align 8
  %_5 = alloca [40 x i8], align 8
  %_4 = alloca [40 x i8], align 8
  %_3 = alloca [24 x i8], align 8
; invoke core::array::iter::<impl core::iter::traits::collect::IntoIterator for [T; N]>::into_iter
  invoke void @"_ZN4core5array4iter94_$LT$impl$u20$core..iter..traits..collect..IntoIterator$u20$for$u20$$u5b$T$u3b$$u20$N$u5d$$GT$9into_iter17ha048ccdd5e2e08c3E"(ptr sret([40 x i8]) align 8 %_5, ptr align 8 %messages)
          to label %bb1 unwind label %funclet_bb13

bb13:                                             ; preds = %funclet_bb13
; call core::ptr::drop_in_place<misanthropic::prompt::Prompt>
  call void @"_ZN4core3ptr49drop_in_place$LT$misanthropic..prompt..Prompt$GT$17hd29181e141a17a3fE"(ptr align 8 %self) #17 [ "funclet"(token %cleanuppad) ]
  cleanupret from %cleanuppad unwind to caller

funclet_bb13:                                     ; preds = %bb5, %bb10, %bb6, %bb4, %bb2, %bb1, %start
  %cleanuppad = cleanuppad within none []
  br label %bb13

bb1:                                              ; preds = %start
; invoke core::iter::traits::iterator::Iterator::map
  invoke void @_ZN4core4iter6traits8iterator8Iterator3map17h78a1367dc208b4c1E(ptr sret([40 x i8]) align 8 %_4, ptr align 8 %_5)
          to label %bb2 unwind label %funclet_bb13

bb2:                                              ; preds = %bb1
; invoke core::iter::traits::iterator::Iterator::collect
  invoke void @_ZN4core4iter6traits8iterator8Iterator7collect17h62aa1b65085a8056E(ptr sret([24 x i8]) align 8 %_3, ptr align 8 %_4)
          to label %bb3 unwind label %funclet_bb13

bb3:                                              ; preds = %bb2
; invoke core::ptr::drop_in_place<alloc::vec::Vec<misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>>>
  invoke void @"_ZN4core3ptr129drop_in_place$LT$alloc..vec..Vec$LT$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$GT$$GT$17h80beb9192a52b8e4E"(ptr align 8 %self)
          to label %bb4 unwind label %funclet_bb5

bb5:                                              ; preds = %funclet_bb5
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %self, ptr align 8 %_3, i64 24, i1 false)
  cleanupret from %cleanuppad1 unwind label %funclet_bb13

funclet_bb5:                                      ; preds = %bb3
  %cleanuppad1 = cleanuppad within none []
  br label %bb5

bb4:                                              ; preds = %bb3
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %self, ptr align 8 %_3, i64 24, i1 false)
; invoke misanthropic::prompt::Prompt::check_turn_order
  invoke void @_ZN12misanthropic6prompt6Prompt16check_turn_order17h080470c1014aab72E(ptr sret([64 x i8]) align 8 %_7, ptr align 8 %self)
          to label %bb6 unwind label %funclet_bb13

bb6:                                              ; preds = %bb4
; invoke <core::result::Result<T,E> as core::ops::try_trait::Try>::branch
  invoke void @"_ZN79_$LT$core..result..Result$LT$T$C$E$GT$$u20$as$u20$core..ops..try_trait..Try$GT$6branch17h6e787bdf34ff2ed1E"(ptr sret([64 x i8]) align 8 %_6, ptr align 8 %_7)
          to label %bb7 unwind label %funclet_bb13

bb7:                                              ; preds = %bb6
  %0 = load i64, ptr %_6, align 8
  %1 = icmp eq i64 %0, -9223372036854775804
  %_9 = select i1 %1, i64 0, i64 1
  %2 = trunc nuw i64 %_9 to i1
  br i1 %2, label %bb10, label %bb9

bb10:                                             ; preds = %bb7
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %residual, ptr align 8 %_6, i64 64, i1 false)
; invoke <core::result::Result<T,F> as core::ops::try_trait::FromResidual<core::result::Result<core::convert::Infallible,E>>>::from_residual
  invoke void @"_ZN153_$LT$core..result..Result$LT$T$C$F$GT$$u20$as$u20$core..ops..try_trait..FromResidual$LT$core..result..Result$LT$core..convert..Infallible$C$E$GT$$GT$$GT$13from_residual17h9cac4c70601d47b0E"(ptr sret([384 x i8]) align 8 %_0, ptr align 8 %residual, ptr align 8 @alloc_87355aedd51e74f601f1a2bd7729f10f)
          to label %bb11 unwind label %funclet_bb13

bb9:                                              ; preds = %bb7
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_11, ptr align 8 %self, i64 384, i1 false)
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_0, ptr align 8 %_11, i64 384, i1 false)
  br label %bb12

bb12:                                             ; preds = %bb11, %bb9
  ret void

bb11:                                             ; preds = %bb10
; call core::ptr::drop_in_place<misanthropic::prompt::Prompt>
  call void @"_ZN4core3ptr49drop_in_place$LT$misanthropic..prompt..Prompt$GT$17hd29181e141a17a3fE"(ptr align 8 %self)
  br label %bb12

bb8:                                              ; No predecessors!
  unreachable
}

; <core::result::Result<T,F> as core::ops::try_trait::FromResidual<core::result::Result<core::convert::Infallible,E>>>::from_residual
; Function Attrs: inlinehint uwtable
define void @"_ZN153_$LT$core..result..Result$LT$T$C$F$GT$$u20$as$u20$core..ops..try_trait..FromResidual$LT$core..result..Result$LT$core..convert..Infallible$C$E$GT$$GT$$GT$13from_residual17h33c183a3cd5d690bE"(ptr sret([360 x i8]) align 8 %_0, ptr align 8 %residual, ptr align 8 %0) unnamed_addr #0 {
start:
  %_3 = alloca [48 x i8], align 8
  %e = alloca [48 x i8], align 8
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %e, ptr align 8 %residual, i64 48, i1 false)
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_3, ptr align 8 %e, i64 48, i1 false)
  %1 = getelementptr inbounds i8, ptr %_0, i64 8
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %1, ptr align 8 %_3, i64 48, i1 false)
  store i64 18, ptr %_0, align 8
  ret void
}

; <core::result::Result<T,F> as core::ops::try_trait::FromResidual<core::result::Result<core::convert::Infallible,E>>>::from_residual
; Function Attrs: inlinehint uwtable
define void @"_ZN153_$LT$core..result..Result$LT$T$C$F$GT$$u20$as$u20$core..ops..try_trait..FromResidual$LT$core..result..Result$LT$core..convert..Infallible$C$E$GT$$GT$$GT$13from_residual17h60913bf8c2b68006E"(ptr sret([360 x i8]) align 8 %_0, ptr align 8 %0, ptr align 8 %1) unnamed_addr #0 {
start:
  %_3 = alloca [48 x i8], align 8
  %residual = alloca [8 x i8], align 8
  store ptr %0, ptr %residual, align 8
  %e = load ptr, ptr %residual, align 8
; call <misanthropic::client::Error as core::convert::From<serde_json::error::Error>>::from
  call void @"_ZN99_$LT$misanthropic..client..Error$u20$as$u20$core..convert..From$LT$serde_json..error..Error$GT$$GT$4from17h2e2843646521c289E"(ptr sret([48 x i8]) align 8 %_3, ptr align 8 %e)
  %2 = getelementptr inbounds i8, ptr %_0, i64 8
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %2, ptr align 8 %_3, i64 48, i1 false)
  store i64 18, ptr %_0, align 8
  ret void
}

; <core::result::Result<T,F> as core::ops::try_trait::FromResidual<core::result::Result<core::convert::Infallible,E>>>::from_residual
; Function Attrs: inlinehint uwtable
define void @"_ZN153_$LT$core..result..Result$LT$T$C$F$GT$$u20$as$u20$core..ops..try_trait..FromResidual$LT$core..result..Result$LT$core..convert..Infallible$C$E$GT$$GT$$GT$13from_residual17h748ff2f7f3335997E"(ptr sret([56 x i8]) align 8 %_0, i64 %0, ptr align 8 %1) unnamed_addr #0 {
start:
  %residual = alloca [8 x i8], align 8
  store i64 %0, ptr %residual, align 8
  %e = load i64, ptr %residual, align 8
  %2 = getelementptr inbounds i8, ptr %_0, i64 8
  store i64 %e, ptr %2, align 8
  store ptr null, ptr %_0, align 8
  ret void
}

; <core::result::Result<T,F> as core::ops::try_trait::FromResidual<core::result::Result<core::convert::Infallible,E>>>::from_residual
; Function Attrs: inlinehint uwtable
define void @"_ZN153_$LT$core..result..Result$LT$T$C$F$GT$$u20$as$u20$core..ops..try_trait..FromResidual$LT$core..result..Result$LT$core..convert..Infallible$C$E$GT$$GT$$GT$13from_residual17h9cac4c70601d47b0E"(ptr sret([384 x i8]) align 8 %_0, ptr align 8 %residual, ptr align 8 %0) unnamed_addr #0 {
start:
  %_3 = alloca [64 x i8], align 8
  %e = alloca [64 x i8], align 8
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %e, ptr align 8 %residual, i64 64, i1 false)
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_3, ptr align 8 %e, i64 64, i1 false)
  %1 = getelementptr inbounds i8, ptr %_0, i64 8
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %1, ptr align 8 %_3, i64 64, i1 false)
  store i64 -9223372036854775808, ptr %_0, align 8
  ret void
}

; <misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role> as core::convert::From<(misanthropic::prompt::message::Role,T)>>::from
; Function Attrs: uwtable
define void @"_ZN180_$LT$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$u20$as$u20$core..convert..From$LT$$LP$misanthropic..prompt..message..Role$C$T$RP$$GT$$GT$4from17h0ff67a9cccd0d117E"(ptr sret([32 x i8]) align 8 %_0, ptr align 8 %_1) unnamed_addr #1 {
start:
  %_4 = alloca [24 x i8], align 8
  %role = load i8, ptr %_1, align 8
  %0 = getelementptr inbounds i8, ptr %_1, i64 8
  %content.0 = load ptr, ptr %0, align 8
  %1 = getelementptr inbounds i8, ptr %0, i64 8
  %content.1 = load i64, ptr %1, align 8
; call <T as core::convert::Into<U>>::into
  call void @"_ZN50_$LT$T$u20$as$u20$core..convert..Into$LT$U$GT$$GT$4into17h503729507de9c474E"(ptr sret([24 x i8]) align 8 %_4, ptr align 1 %content.0, i64 %content.1, ptr align 8 @alloc_e333a51a7d3d4141e0beb547b79b3281)
  %2 = getelementptr inbounds i8, ptr %_0, i64 24
  store i8 %role, ptr %2, align 8
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_0, ptr align 8 %_4, i64 24, i1 false)
  ret void
}

; <&T as core::fmt::Debug>::fmt
; Function Attrs: uwtable
define zeroext i1 @"_ZN42_$LT$$RF$T$u20$as$u20$core..fmt..Debug$GT$3fmt17h00e57a321a275cfeE"(ptr align 8 %self, ptr align 8 %f) unnamed_addr #1 {
start:
  %_3 = load ptr, ptr %self, align 8
; call <serde_json::error::Error as core::fmt::Debug>::fmt
  %_0 = call zeroext i1 @"_ZN61_$LT$serde_json..error..Error$u20$as$u20$core..fmt..Debug$GT$3fmt17h353ee308a8389ff0E"(ptr align 8 %_3, ptr align 8 %f)
  ret i1 %_0
}

; <&T as core::fmt::Debug>::fmt
; Function Attrs: uwtable
define zeroext i1 @"_ZN42_$LT$$RF$T$u20$as$u20$core..fmt..Debug$GT$3fmt17hd077c0b49957299fE"(ptr align 8 %self, ptr align 8 %f) unnamed_addr #1 {
start:
  %_3 = load ptr, ptr %self, align 8
; call <misanthropic::client::AnthropicError as core::fmt::Debug>::fmt
  %_0 = call zeroext i1 @"_ZN73_$LT$misanthropic..client..AnthropicError$u20$as$u20$core..fmt..Debug$GT$3fmt17hf27a5a97a58bbc9cE"(ptr align 8 %_3, ptr align 8 %f)
  ret i1 %_0
}

; core::fmt::num::<impl core::fmt::Debug for u16>::fmt
; Function Attrs: inlinehint uwtable
define hidden zeroext i1 @"_ZN4core3fmt3num50_$LT$impl$u20$core..fmt..Debug$u20$for$u20$u16$GT$3fmt17h7955cd73c1ff96bdE"(ptr align 2 %self, ptr align 8 %f) unnamed_addr #0 {
start:
  %_0 = alloca [1 x i8], align 1
  %0 = getelementptr inbounds i8, ptr %f, i64 16
  %_4 = load i32, ptr %0, align 8
  %_3 = and i32 %_4, 33554432
  %1 = icmp eq i32 %_3, 0
  br i1 %1, label %bb2, label %bb1

bb2:                                              ; preds = %start
  %2 = getelementptr inbounds i8, ptr %f, i64 16
  %_6 = load i32, ptr %2, align 8
  %_5 = and i32 %_6, 67108864
  %3 = icmp eq i32 %_5, 0
  br i1 %3, label %bb4, label %bb3

bb1:                                              ; preds = %start
; call core::fmt::num::<impl core::fmt::LowerHex for u16>::fmt
  %4 = call zeroext i1 @"_ZN4core3fmt3num53_$LT$impl$u20$core..fmt..LowerHex$u20$for$u20$u16$GT$3fmt17hce7a69d038e0c81fE"(ptr align 2 %self, ptr align 8 %f)
  %5 = zext i1 %4 to i8
  store i8 %5, ptr %_0, align 1
  br label %bb6

bb4:                                              ; preds = %bb2
; call core::fmt::num::imp::<impl core::fmt::Display for u16>::fmt
  %6 = call zeroext i1 @"_ZN4core3fmt3num3imp52_$LT$impl$u20$core..fmt..Display$u20$for$u20$u16$GT$3fmt17h3fe79bb4702b6dbfE"(ptr align 2 %self, ptr align 8 %f)
  %7 = zext i1 %6 to i8
  store i8 %7, ptr %_0, align 1
  br label %bb5

bb3:                                              ; preds = %bb2
; call core::fmt::num::<impl core::fmt::UpperHex for u16>::fmt
  %8 = call zeroext i1 @"_ZN4core3fmt3num53_$LT$impl$u20$core..fmt..UpperHex$u20$for$u20$u16$GT$3fmt17h6629f1e170b83e4cE"(ptr align 2 %self, ptr align 8 %f)
  %9 = zext i1 %8 to i8
  store i8 %9, ptr %_0, align 1
  br label %bb5

bb5:                                              ; preds = %bb3, %bb4
  br label %bb6

bb6:                                              ; preds = %bb1, %bb5
  %10 = load i8, ptr %_0, align 1
  %11 = trunc nuw i8 %10 to i1
  ret i1 %11
}

; core::num::<impl usize>::unchecked_add::precondition_check
; Function Attrs: inlinehint nounwind uwtable
define hidden void @"_ZN4core3num23_$LT$impl$u20$usize$GT$13unchecked_add18precondition_check17h947eae1af0984b8bE"(i64 %lhs, i64 %rhs) unnamed_addr #2 {
start:
  %0 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %lhs, i64 %rhs)
  %_5.0 = extractvalue { i64, i1 } %0, 0
  %_5.1 = extractvalue { i64, i1 } %0, 1
  br i1 %_5.1, label %bb1, label %bb2

bb2:                                              ; preds = %start
  ret void

bb1:                                              ; preds = %start
; call core::panicking::panic_nounwind
  call void @_ZN4core9panicking14panic_nounwind17hb115782c8cb05dd0E(ptr align 1 @alloc_3e1ebac14318b612ab4efabc52799932, i64 186) #15
  unreachable
}

; core::ops::function::FnMut::call_mut
; Function Attrs: inlinehint uwtable
define hidden void @_ZN4core3ops8function5FnMut8call_mut17hc36b141d03e00966E(ptr sret([32 x i8]) align 8 %_0, ptr align 1 %_1, ptr align 8 %0) unnamed_addr #0 {
start:
  %_2 = alloca [24 x i8], align 8
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_2, ptr align 8 %0, i64 24, i1 false)
; call <T as core::convert::Into<U>>::into
  call void @"_ZN50_$LT$T$u20$as$u20$core..convert..Into$LT$U$GT$$GT$4into17hbd967f24024c959cE"(ptr sret([32 x i8]) align 8 %_0, ptr align 8 %_2, ptr align 8 @alloc_c08768be04b52678f33214e18ddf67cd)
  ret void
}

; core::ops::try_trait::NeverShortCircuit<T>::wrap_mut_2::{{closure}}
; Function Attrs: inlinehint uwtable
define void @"_ZN4core3ops9try_trait26NeverShortCircuit$LT$T$GT$10wrap_mut_228_$u7b$$u7b$closure$u7d$$u7d$17h49c81d74a5bb8055E"(ptr align 8 %_1, ptr align 8 %b) unnamed_addr #0 {
start:
  %_6 = alloca [24 x i8], align 8
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_6, ptr align 8 %b, i64 24, i1 false)
; call core::iter::adapters::map::map_fold::{{closure}}
  call void @"_ZN4core4iter8adapters3map8map_fold28_$u7b$$u7b$closure$u7d$$u7d$17hb4ea91fb1768858dE"(ptr align 8 %_1, ptr align 8 %_6)
  ret void
}

; core::pin::Pin<Ptr>::new_unchecked
; Function Attrs: alwaysinline uwtable
define align 8 ptr @"_ZN4core3pin14Pin$LT$Ptr$GT$13new_unchecked17h4363a55dc88298a2E"(ptr align 8 %pointer) unnamed_addr #3 {
start:
  ret ptr %pointer
}

; core::pin::Pin<Ptr>::new_unchecked
; Function Attrs: alwaysinline uwtable
define align 8 ptr @"_ZN4core3pin14Pin$LT$Ptr$GT$13new_unchecked17h71ce3fbabaf95e0dE"(ptr align 8 %pointer) unnamed_addr #3 {
start:
  ret ptr %pointer
}

; core::pin::Pin<Ptr>::new_unchecked
; Function Attrs: alwaysinline uwtable
define align 8 ptr @"_ZN4core3pin14Pin$LT$Ptr$GT$13new_unchecked17he06e1a4e065a9ec7E"(ptr align 8 %pointer) unnamed_addr #3 {
start:
  ret ptr %pointer
}

; core::ptr::drop_in_place<&misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>>
; Function Attrs: inlinehint uwtable
define hidden void @"_ZN4core3ptr110drop_in_place$LT$$RF$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$GT$17hba77a9df1ce226a8E"(ptr align 8 %_1) unnamed_addr #0 {
start:
  ret void
}

; core::ptr::drop_in_place<core::iter::adapters::map::map_fold<(misanthropic::prompt::message::Role,&str),misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>,(),<(misanthropic::prompt::message::Role,&str) as core::convert::Into<misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>>>::into,core::iter::traits::iterator::Iterator::for_each::call<misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>,alloc::vec::Vec<misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>>::extend_trusted<core::iter::adapters::map::Map<core::array::iter::IntoIter<(misanthropic::prompt::message::Role,&str),1_usize>,<(misanthropic::prompt::message::Role,&str) as core::convert::Into<misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>>>::into>>::{{closure}}>::{{closure}}>::{{closure}}>
; Function Attrs: uwtable
define void @"_ZN4core3ptr1112drop_in_place$LT$core..iter..adapters..map..map_fold$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$C$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$C$$LP$$RP$$C$$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$u20$as$u20$core..convert..Into$LT$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$GT$$GT$..into$C$core..iter..traits..iterator..Iterator..for_each..call$LT$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$C$alloc..vec..Vec$LT$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$GT$..extend_trusted$LT$core..iter..adapters..map..Map$LT$core..array..iter..IntoIter$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$C$1_usize$GT$$C$$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$u20$as$u20$core..convert..Into$LT$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$GT$$GT$..into$GT$$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$17hae097899df264fd7E"(ptr align 8 %_1) unnamed_addr #1 {
start:
; call core::ptr::drop_in_place<core::iter::traits::iterator::Iterator::for_each::call<misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>,alloc::vec::Vec<misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>>::extend_trusted<core::iter::adapters::map::Map<core::array::iter::IntoIter<(misanthropic::prompt::message::Role,&str),1_usize>,<(misanthropic::prompt::message::Role,&str) as core::convert::Into<misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>>>::into>>::{{closure}}>::{{closure}}>
  call void @"_ZN4core3ptr691drop_in_place$LT$core..iter..traits..iterator..Iterator..for_each..call$LT$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$C$alloc..vec..Vec$LT$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$GT$..extend_trusted$LT$core..iter..adapters..map..Map$LT$core..array..iter..IntoIter$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$C$1_usize$GT$$C$$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$u20$as$u20$core..convert..Into$LT$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$GT$$GT$..into$GT$$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$17hc82beb9dbfa87dfdE"(ptr align 8 %_1)
  ret void
}

; core::ptr::drop_in_place<core::array::iter::IntoIter<(misanthropic::prompt::message::Role,&str),1_usize>>
; Function Attrs: uwtable
define void @"_ZN4core3ptr119drop_in_place$LT$core..array..iter..IntoIter$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$C$1_usize$GT$$GT$17h777d79445066cad3E"(ptr align 8 %_1) unnamed_addr #1 personality ptr @__CxxFrameHandler3 {
start:
; invoke <core::array::iter::IntoIter<T,_> as core::ops::drop::Drop>::drop
  invoke void @"_ZN82_$LT$core..array..iter..IntoIter$LT$T$C$_$GT$$u20$as$u20$core..ops..drop..Drop$GT$4drop17h351356d19c94e25aE"(ptr align 8 %_1)
          to label %bb4 unwind label %funclet_bb3

bb3:                                              ; preds = %funclet_bb3
; call core::ptr::drop_in_place<core::array::iter::iter_inner::PolymorphicIter<[core::mem::maybe_uninit::MaybeUninit<(misanthropic::prompt::message::Role,&str)>; 1]>>
  call void @"_ZN4core3ptr193drop_in_place$LT$core..array..iter..iter_inner..PolymorphicIter$LT$$u5b$core..mem..maybe_uninit..MaybeUninit$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$GT$$u3b$$u20$1$u5d$$GT$$GT$17hde1e6b6c239e217dE"(ptr align 8 %_1) #17 [ "funclet"(token %cleanuppad) ]
  cleanupret from %cleanuppad unwind to caller

funclet_bb3:                                      ; preds = %start
  %cleanuppad = cleanuppad within none []
  br label %bb3

bb4:                                              ; preds = %start
; call core::ptr::drop_in_place<core::array::iter::iter_inner::PolymorphicIter<[core::mem::maybe_uninit::MaybeUninit<(misanthropic::prompt::message::Role,&str)>; 1]>>
  call void @"_ZN4core3ptr193drop_in_place$LT$core..array..iter..iter_inner..PolymorphicIter$LT$$u5b$core..mem..maybe_uninit..MaybeUninit$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$GT$$u3b$$u20$1$u5d$$GT$$GT$17hde1e6b6c239e217dE"(ptr align 8 %_1)
  ret void
}

; core::ptr::drop_in_place<alloc::sync::Weak<core::option::Option<alloc::string::String>,&alloc::alloc::Global>>
; Function Attrs: uwtable
define void @"_ZN4core3ptr122drop_in_place$LT$alloc..sync..Weak$LT$core..option..Option$LT$alloc..string..String$GT$$C$$RF$alloc..alloc..Global$GT$$GT$17h0fed26da7cd7816cE"(ptr align 8 %_1) unnamed_addr #1 {
start:
; call <alloc::sync::Weak<T,A> as core::ops::drop::Drop>::drop
  call void @"_ZN72_$LT$alloc..sync..Weak$LT$T$C$A$GT$$u20$as$u20$core..ops..drop..Drop$GT$4drop17h4332bdb7e5fd6c2bE"(ptr align 8 %_1)
  ret void
}

; core::ptr::drop_in_place<misanthropic::client::Client::stream<&misanthropic::prompt::Prompt>::{{closure}}>
; Function Attrs: uwtable
define void @"_ZN4core3ptr126drop_in_place$LT$misanthropic..client..Client..stream$LT$$RF$misanthropic..prompt..Prompt$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$17h9abc3d68019e8a21E"(ptr align 8 %_1) unnamed_addr #1 personality ptr @__CxxFrameHandler3 {
start:
  %_49 = alloca [1 x i8], align 1
  %_48 = alloca [1 x i8], align 1
  %0 = getelementptr inbounds i8, ptr %_1, i64 1185
  %1 = load i8, ptr %0, align 1
  %_80 = zext i8 %1 to i32
  switch i32 %_80, label %bb24 [
    i32 0, label %bb20
    i32 3, label %bb23
  ]

bb24:                                             ; preds = %start
  ret void

bb20:                                             ; preds = %start
  br label %bb21

bb23:                                             ; preds = %start
  %2 = getelementptr inbounds i8, ptr %_1, i64 72
; invoke core::ptr::drop_in_place<misanthropic::client::Client::request<serde_json::value::Value>::{{closure}}>
  invoke void @"_ZN4core3ptr119drop_in_place$LT$misanthropic..client..Client..request$LT$serde_json..value..Value$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$17h3f71628b587fadc0E"(ptr align 8 %2)
          to label %bb3 unwind label %funclet_bb11

bb21:                                             ; preds = %bb20
  ret void

bb11:                                             ; preds = %funclet_bb11
  store i8 0, ptr %_48, align 1
  store i8 0, ptr %_49, align 1
  %3 = getelementptr inbounds i8, ptr %_1, i64 1184
  store i8 0, ptr %3, align 8
  cleanupret from %cleanuppad unwind label %funclet_bb10

funclet_bb11:                                     ; preds = %bb23
  %cleanuppad = cleanuppad within none []
  br label %bb11

bb3:                                              ; preds = %bb23
  store i8 0, ptr %_48, align 1
  store i8 0, ptr %_49, align 1
  %4 = getelementptr inbounds i8, ptr %_1, i64 1184
  store i8 0, ptr %4, align 8
  ret void

bb10:                                             ; preds = %funclet_bb10
  cleanupret from %cleanuppad1 unwind to caller

funclet_bb10:                                     ; preds = %bb11
  %cleanuppad1 = cleanuppad within none []
  br label %bb10
}

; core::ptr::drop_in_place<core::ops::try_trait::NeverShortCircuit<()>::wrap_mut_2<(),(misanthropic::prompt::message::Role,&str),core::iter::adapters::map::map_fold<(misanthropic::prompt::message::Role,&str),misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>,(),<(misanthropic::prompt::message::Role,&str) as core::convert::Into<misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>>>::into,core::iter::traits::iterator::Iterator::for_each::call<misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>,alloc::vec::Vec<misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>>::extend_trusted<core::iter::adapters::map::Map<core::array::iter::IntoIter<(misanthropic::prompt::message::Role,&str),1_usize>,<(misanthropic::prompt::message::Role,&str) as core::convert::Into<misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>>>::into>>::{{closure}}>::{{closure}}>::{{closure}}>::{{closure}}>
; Function Attrs: uwtable
define void @"_ZN4core3ptr1283drop_in_place$LT$core..ops..try_trait..NeverShortCircuit$LT$$LP$$RP$$GT$..wrap_mut_2$LT$$LP$$RP$$C$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$C$core..iter..adapters..map..map_fold$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$C$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$C$$LP$$RP$$C$$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$u20$as$u20$core..convert..Into$LT$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$GT$$GT$..into$C$core..iter..traits..iterator..Iterator..for_each..call$LT$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$C$alloc..vec..Vec$LT$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$GT$..extend_trusted$LT$core..iter..adapters..map..Map$LT$core..array..iter..IntoIter$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$C$1_usize$GT$$C$$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$u20$as$u20$core..convert..Into$LT$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$GT$$GT$..into$GT$$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$17haddf13c8d6695bafE"(ptr align 8 %_1) unnamed_addr #1 {
start:
; call core::ptr::drop_in_place<core::iter::adapters::map::map_fold<(misanthropic::prompt::message::Role,&str),misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>,(),<(misanthropic::prompt::message::Role,&str) as core::convert::Into<misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>>>::into,core::iter::traits::iterator::Iterator::for_each::call<misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>,alloc::vec::Vec<misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>>::extend_trusted<core::iter::adapters::map::Map<core::array::iter::IntoIter<(misanthropic::prompt::message::Role,&str),1_usize>,<(misanthropic::prompt::message::Role,&str) as core::convert::Into<misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>>>::into>>::{{closure}}>::{{closure}}>::{{closure}}>
  call void @"_ZN4core3ptr1112drop_in_place$LT$core..iter..adapters..map..map_fold$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$C$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$C$$LP$$RP$$C$$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$u20$as$u20$core..convert..Into$LT$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$GT$$GT$..into$C$core..iter..traits..iterator..Iterator..for_each..call$LT$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$C$alloc..vec..Vec$LT$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$GT$..extend_trusted$LT$core..iter..adapters..map..Map$LT$core..array..iter..IntoIter$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$C$1_usize$GT$$C$$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$u20$as$u20$core..convert..Into$LT$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$GT$$GT$..into$GT$$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$17hae097899df264fd7E"(ptr align 8 %_1)
  ret void
}

; core::ptr::read_volatile::precondition_check
; Function Attrs: inlinehint nounwind uwtable
define hidden void @_ZN4core3ptr13read_volatile18precondition_check17h3c045cae23cc78bcE(ptr %addr, i64 %align, i1 zeroext %is_zst) unnamed_addr #2 personality ptr @__CxxFrameHandler3 {
start:
  %0 = alloca [4 x i8], align 4
  %_8 = alloca [48 x i8], align 8
  %1 = call i64 @llvm.ctpop.i64(i64 %align)
  %2 = trunc i64 %1 to i32
  store i32 %2, ptr %0, align 4
  %_12 = load i32, ptr %0, align 4
  %3 = icmp eq i32 %_12, 1
  br i1 %3, label %bb7, label %bb8

bb7:                                              ; preds = %start
  %_10 = ptrtoint ptr %addr to i64
  %_11 = sub i64 %align, 1
  %_9 = and i64 %_10, %_11
  %4 = icmp eq i64 %_9, 0
  br i1 %4, label %bb3, label %bb4

bb8:                                              ; preds = %start
  store ptr @alloc_e92e94d0ff530782b571cfd99ec66aef, ptr %_8, align 8
  %5 = getelementptr inbounds i8, ptr %_8, i64 8
  store i64 1, ptr %5, align 8
  %6 = load ptr, ptr @anon.9bb7cee0307838987e4b4b15e8b33297.0, align 8
  %7 = load i64, ptr getelementptr inbounds (i8, ptr @anon.9bb7cee0307838987e4b4b15e8b33297.0, i64 8), align 8
  %8 = getelementptr inbounds i8, ptr %_8, i64 32
  store ptr %6, ptr %8, align 8
  %9 = getelementptr inbounds i8, ptr %8, i64 8
  store i64 %7, ptr %9, align 8
  %10 = getelementptr inbounds i8, ptr %_8, i64 16
  store ptr inttoptr (i64 8 to ptr), ptr %10, align 8
  %11 = getelementptr inbounds i8, ptr %10, i64 8
  store i64 0, ptr %11, align 8
; invoke core::panicking::panic_fmt
  invoke void @_ZN4core9panicking9panic_fmt17h6b7e0a7dad869f5aE(ptr align 8 %_8, ptr align 8 @alloc_d5565c3c200d27d008540d6a6ddd052a) #16
          to label %unreachable unwind label %cs_terminate

bb3:                                              ; preds = %bb7
  br i1 %is_zst, label %bb5, label %bb6

bb4:                                              ; preds = %bb7
  br label %bb2

bb6:                                              ; preds = %bb3
  %_6 = icmp eq i64 %_10, 0
  %_4 = xor i1 %_6, true
  br i1 %_4, label %bb1, label %bb2

bb5:                                              ; preds = %bb3
  br label %bb1

bb2:                                              ; preds = %bb4, %bb6
; call core::panicking::panic_nounwind
  call void @_ZN4core9panicking14panic_nounwind17hb115782c8cb05dd0E(ptr align 1 @alloc_2dff866d8f4414dd3e87cf8872473df8, i64 227) #15
  unreachable

bb1:                                              ; preds = %bb5, %bb6
  ret void

cs_terminate:                                     ; preds = %bb8
  %catchswitch = catchswitch within none [label %cp_terminate] unwind to caller

cp_terminate:                                     ; preds = %cs_terminate
  %catchpad = catchpad within %catchswitch [ptr null, i32 64, ptr null]
; call core::panicking::panic_cannot_unwind
  call void @_ZN4core9panicking19panic_cannot_unwind17h8a970db44b3fe0a2E() #19 [ "funclet"(token %catchpad) ]
  unreachable

unreachable:                                      ; preds = %bb8
  unreachable
}

; core::ptr::drop_in_place<core::array::iter::iter_inner::PolymorphicIter<[core::mem::maybe_uninit::MaybeUninit<(misanthropic::prompt::message::Role,&str)>]>::try_fold<(),core::ops::try_trait::NeverShortCircuit<()>::wrap_mut_2<(),(misanthropic::prompt::message::Role,&str),core::iter::adapters::map::map_fold<(misanthropic::prompt::message::Role,&str),misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>,(),<(misanthropic::prompt::message::Role,&str) as core::convert::Into<misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>>>::into,core::iter::traits::iterator::Iterator::for_each::call<misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>,alloc::vec::Vec<misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>>::extend_trusted<core::iter::adapters::map::Map<core::array::iter::IntoIter<(misanthropic::prompt::message::Role,&str),1_usize>,<(misanthropic::prompt::message::Role,&str) as core::convert::Into<misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>>>::into>>::{{closure}}>::{{closure}}>::{{closure}}>::{{closure}},core::ops::try_trait::NeverShortCircuit<()>>::{{closure}}>
; Function Attrs: uwtable
define void @"_ZN4core3ptr1560drop_in_place$LT$core..array..iter..iter_inner..PolymorphicIter$LT$$u5b$core..mem..maybe_uninit..MaybeUninit$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$GT$$u5d$$GT$..try_fold$LT$$LP$$RP$$C$core..ops..try_trait..NeverShortCircuit$LT$$LP$$RP$$GT$..wrap_mut_2$LT$$LP$$RP$$C$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$C$core..iter..adapters..map..map_fold$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$C$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$C$$LP$$RP$$C$$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$u20$as$u20$core..convert..Into$LT$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$GT$$GT$..into$C$core..iter..traits..iterator..Iterator..for_each..call$LT$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$C$alloc..vec..Vec$LT$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$GT$..extend_trusted$LT$core..iter..adapters..map..Map$LT$core..array..iter..IntoIter$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$C$1_usize$GT$$C$$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$u20$as$u20$core..convert..Into$LT$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$GT$$GT$..into$GT$$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$..$u7b$$u7b$closure$u7d$$u7d$$C$core..ops..try_trait..NeverShortCircuit$LT$$LP$$RP$$GT$$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$17h127e08b51e4d053cE"(ptr align 8 %_1) unnamed_addr #1 {
start:
  %0 = getelementptr inbounds i8, ptr %_1, i64 16
; call core::ptr::drop_in_place<core::ops::try_trait::NeverShortCircuit<()>::wrap_mut_2<(),(misanthropic::prompt::message::Role,&str),core::iter::adapters::map::map_fold<(misanthropic::prompt::message::Role,&str),misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>,(),<(misanthropic::prompt::message::Role,&str) as core::convert::Into<misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>>>::into,core::iter::traits::iterator::Iterator::for_each::call<misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>,alloc::vec::Vec<misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>>::extend_trusted<core::iter::adapters::map::Map<core::array::iter::IntoIter<(misanthropic::prompt::message::Role,&str),1_usize>,<(misanthropic::prompt::message::Role,&str) as core::convert::Into<misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>>>::into>>::{{closure}}>::{{closure}}>::{{closure}}>::{{closure}}>
  call void @"_ZN4core3ptr1283drop_in_place$LT$core..ops..try_trait..NeverShortCircuit$LT$$LP$$RP$$GT$..wrap_mut_2$LT$$LP$$RP$$C$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$C$core..iter..adapters..map..map_fold$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$C$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$C$$LP$$RP$$C$$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$u20$as$u20$core..convert..Into$LT$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$GT$$GT$..into$C$core..iter..traits..iterator..Iterator..for_each..call$LT$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$C$alloc..vec..Vec$LT$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$GT$..extend_trusted$LT$core..iter..adapters..map..Map$LT$core..array..iter..IntoIter$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$C$1_usize$GT$$C$$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$u20$as$u20$core..convert..Into$LT$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$GT$$GT$..into$GT$$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$17haddf13c8d6695bafE"(ptr align 8 %0)
  ret void
}

; core::ptr::drop_in_place<core::array::iter::iter_inner::PolymorphicIter<[core::mem::maybe_uninit::MaybeUninit<(misanthropic::prompt::message::Role,&str)>; 1]>>
; Function Attrs: uwtable
define void @"_ZN4core3ptr193drop_in_place$LT$core..array..iter..iter_inner..PolymorphicIter$LT$$u5b$core..mem..maybe_uninit..MaybeUninit$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$GT$$u3b$$u20$1$u5d$$GT$$GT$17hde1e6b6c239e217dE"(ptr align 8 %_1) unnamed_addr #1 {
start:
; call <core::array::iter::iter_inner::PolymorphicIter<DATA> as core::ops::drop::Drop>::drop
  call void @"_ZN100_$LT$core..array..iter..iter_inner..PolymorphicIter$LT$DATA$GT$$u20$as$u20$core..ops..drop..Drop$GT$4drop17he94e64ad313a7e26E"(ptr align 8 %_1)
  ret void
}

; core::ptr::drop_in_place<u16>
; Function Attrs: inlinehint uwtable
define hidden void @"_ZN4core3ptr24drop_in_place$LT$u16$GT$17h62f7ec83dd7e444fE"(ptr align 2 %_1) unnamed_addr #0 {
start:
  ret void
}

; core::ptr::drop_in_place<&usize>
; Function Attrs: inlinehint uwtable
define hidden void @"_ZN4core3ptr30drop_in_place$LT$$RF$usize$GT$17h1912e4f6fa8d7396E"(ptr align 8 %_1) unnamed_addr #0 {
start:
  ret void
}

; core::ptr::drop_in_place<&&str>
; Function Attrs: inlinehint uwtable
define hidden void @"_ZN4core3ptr32drop_in_place$LT$$RF$$RF$str$GT$17h1a198731d4126986E"(ptr align 8 %_1) unnamed_addr #0 {
start:
  ret void
}

; core::ptr::drop_in_place<core::iter::adapters::map::Map<core::array::iter::IntoIter<(misanthropic::prompt::message::Role,&str),1_usize>,<(misanthropic::prompt::message::Role,&str) as core::convert::Into<misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>>>::into>>
; Function Attrs: uwtable
define void @"_ZN4core3ptr351drop_in_place$LT$core..iter..adapters..map..Map$LT$core..array..iter..IntoIter$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$C$1_usize$GT$$C$$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$u20$as$u20$core..convert..Into$LT$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$GT$$GT$..into$GT$$GT$17h290ac583dfbf459aE"(ptr align 8 %_1) unnamed_addr #1 {
start:
; call core::ptr::drop_in_place<core::array::iter::IntoIter<(misanthropic::prompt::message::Role,&str),1_usize>>
  call void @"_ZN4core3ptr119drop_in_place$LT$core..array..iter..IntoIter$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$C$1_usize$GT$$GT$17h777d79445066cad3E"(ptr align 8 %_1)
  ret void
}

; core::ptr::drop_in_place<&alloc::string::String>
; Function Attrs: inlinehint uwtable
define hidden void @"_ZN4core3ptr46drop_in_place$LT$$RF$alloc..string..String$GT$17he820c4da257afb15E"(ptr align 8 %_1) unnamed_addr #0 {
start:
  ret void
}

; core::ptr::drop_in_place<&reqwest::error::Error>
; Function Attrs: inlinehint uwtable
define hidden void @"_ZN4core3ptr46drop_in_place$LT$$RF$reqwest..error..Error$GT$17h14afc43b28984611E"(ptr align 8 %_1) unnamed_addr #0 {
start:
  ret void
}

; core::ptr::drop_in_place<&serde_json::error::Error>
; Function Attrs: inlinehint uwtable
define hidden void @"_ZN4core3ptr49drop_in_place$LT$$RF$serde_json..error..Error$GT$17h1f9b31e79105f274E"(ptr align 8 %_1) unnamed_addr #0 {
start:
  ret void
}

; core::ptr::drop_in_place<misanthropic::client::Client>
; Function Attrs: uwtable
define void @"_ZN4core3ptr49drop_in_place$LT$misanthropic..client..Client$GT$17h4d0925dfa4db6766E"(ptr align 8 %_1) unnamed_addr #1 personality ptr @__CxxFrameHandler3 {
start:
; invoke core::ptr::drop_in_place<reqwest::async_impl::client::Client>
  invoke void @"_ZN4core3ptr56drop_in_place$LT$reqwest..async_impl..client..Client$GT$17h323d6264c46a934eE"(ptr align 8 %_1)
          to label %bb14 unwind label %funclet_bb8

bb8:                                              ; preds = %funclet_bb8
  %0 = getelementptr inbounds i8, ptr %_1, i64 8
; call core::ptr::drop_in_place<alloc::sync::Arc<misanthropic::key::unencrypted::Key>>
  call void @"_ZN4core3ptr80drop_in_place$LT$alloc..sync..Arc$LT$misanthropic..key..unencrypted..Key$GT$$GT$17h56c2e12bbc997854E"(ptr align 8 %0) #17 [ "funclet"(token %cleanuppad) ]
  cleanupret from %cleanuppad unwind label %funclet_bb7

funclet_bb8:                                      ; preds = %start
  %cleanuppad = cleanuppad within none []
  br label %bb8

bb14:                                             ; preds = %start
  %1 = getelementptr inbounds i8, ptr %_1, i64 8
; invoke core::ptr::drop_in_place<alloc::sync::Arc<misanthropic::key::unencrypted::Key>>
  invoke void @"_ZN4core3ptr80drop_in_place$LT$alloc..sync..Arc$LT$misanthropic..key..unencrypted..Key$GT$$GT$17h56c2e12bbc997854E"(ptr align 8 %1)
          to label %bb13 unwind label %funclet_bb7

bb7:                                              ; preds = %funclet_bb7
  %2 = getelementptr inbounds i8, ptr %_1, i64 16
; call core::ptr::drop_in_place<alloc::sync::Arc<url::Url>>
  call void @"_ZN4core3ptr53drop_in_place$LT$alloc..sync..Arc$LT$url..Url$GT$$GT$17hd7ac9074da8d1f83E"(ptr align 8 %2) #17 [ "funclet"(token %cleanuppad1) ]
  cleanupret from %cleanuppad1 unwind label %funclet_bb6

funclet_bb7:                                      ; preds = %bb8, %bb14
  %cleanuppad1 = cleanuppad within none []
  br label %bb7

bb13:                                             ; preds = %bb14
  %3 = getelementptr inbounds i8, ptr %_1, i64 16
; invoke core::ptr::drop_in_place<alloc::sync::Arc<url::Url>>
  invoke void @"_ZN4core3ptr53drop_in_place$LT$alloc..sync..Arc$LT$url..Url$GT$$GT$17hd7ac9074da8d1f83E"(ptr align 8 %3)
          to label %bb12 unwind label %funclet_bb6

bb6:                                              ; preds = %funclet_bb6
  %4 = getelementptr inbounds i8, ptr %_1, i64 24
; call core::ptr::drop_in_place<alloc::sync::Arc<url::Url>>
  call void @"_ZN4core3ptr53drop_in_place$LT$alloc..sync..Arc$LT$url..Url$GT$$GT$17hd7ac9074da8d1f83E"(ptr align 8 %4) #17 [ "funclet"(token %cleanuppad2) ]
  cleanupret from %cleanuppad2 unwind label %funclet_bb5

funclet_bb6:                                      ; preds = %bb7, %bb13
  %cleanuppad2 = cleanuppad within none []
  br label %bb6

bb12:                                             ; preds = %bb13
  %5 = getelementptr inbounds i8, ptr %_1, i64 24
; invoke core::ptr::drop_in_place<alloc::sync::Arc<url::Url>>
  invoke void @"_ZN4core3ptr53drop_in_place$LT$alloc..sync..Arc$LT$url..Url$GT$$GT$17hd7ac9074da8d1f83E"(ptr align 8 %5)
          to label %bb11 unwind label %funclet_bb5

bb5:                                              ; preds = %funclet_bb5
  %6 = getelementptr inbounds i8, ptr %_1, i64 32
; call core::ptr::drop_in_place<alloc::sync::Arc<url::Url>>
  call void @"_ZN4core3ptr53drop_in_place$LT$alloc..sync..Arc$LT$url..Url$GT$$GT$17hd7ac9074da8d1f83E"(ptr align 8 %6) #17 [ "funclet"(token %cleanuppad3) ]
  cleanupret from %cleanuppad3 unwind label %funclet_bb4

funclet_bb5:                                      ; preds = %bb6, %bb12
  %cleanuppad3 = cleanuppad within none []
  br label %bb5

bb11:                                             ; preds = %bb12
  %7 = getelementptr inbounds i8, ptr %_1, i64 32
; invoke core::ptr::drop_in_place<alloc::sync::Arc<url::Url>>
  invoke void @"_ZN4core3ptr53drop_in_place$LT$alloc..sync..Arc$LT$url..Url$GT$$GT$17hd7ac9074da8d1f83E"(ptr align 8 %7)
          to label %bb10 unwind label %funclet_bb4

bb4:                                              ; preds = %funclet_bb4
  %8 = getelementptr inbounds i8, ptr %_1, i64 40
; call core::ptr::drop_in_place<alloc::sync::Arc<url::Url>>
  call void @"_ZN4core3ptr53drop_in_place$LT$alloc..sync..Arc$LT$url..Url$GT$$GT$17hd7ac9074da8d1f83E"(ptr align 8 %8) #17 [ "funclet"(token %cleanuppad4) ]
  cleanupret from %cleanuppad4 unwind label %funclet_bb3

funclet_bb4:                                      ; preds = %bb5, %bb11
  %cleanuppad4 = cleanuppad within none []
  br label %bb4

bb10:                                             ; preds = %bb11
  %9 = getelementptr inbounds i8, ptr %_1, i64 40
; invoke core::ptr::drop_in_place<alloc::sync::Arc<url::Url>>
  invoke void @"_ZN4core3ptr53drop_in_place$LT$alloc..sync..Arc$LT$url..Url$GT$$GT$17hd7ac9074da8d1f83E"(ptr align 8 %9)
          to label %bb9 unwind label %funclet_bb3

bb3:                                              ; preds = %funclet_bb3
  %10 = getelementptr inbounds i8, ptr %_1, i64 48
; call core::ptr::drop_in_place<alloc::sync::Arc<core::option::Option<alloc::string::String>>>
  call void @"_ZN4core3ptr94drop_in_place$LT$alloc..sync..Arc$LT$core..option..Option$LT$alloc..string..String$GT$$GT$$GT$17hd380e56ac09759d7E"(ptr align 8 %10) #17 [ "funclet"(token %cleanuppad5) ]
  cleanupret from %cleanuppad5 unwind to caller

funclet_bb3:                                      ; preds = %bb4, %bb10
  %cleanuppad5 = cleanuppad within none []
  br label %bb3

bb9:                                              ; preds = %bb10
  %11 = getelementptr inbounds i8, ptr %_1, i64 48
; call core::ptr::drop_in_place<alloc::sync::Arc<core::option::Option<alloc::string::String>>>
  call void @"_ZN4core3ptr94drop_in_place$LT$alloc..sync..Arc$LT$core..option..Option$LT$alloc..string..String$GT$$GT$$GT$17hd380e56ac09759d7E"(ptr align 8 %11)
  ret void
}

; core::ptr::drop_in_place<alloc::vec::Vec<misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>>::extend_trusted<core::iter::adapters::map::Map<core::array::iter::IntoIter<(misanthropic::prompt::message::Role,&str),1_usize>,<(misanthropic::prompt::message::Role,&str) as core::convert::Into<misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>>>::into>>::{{closure}}>
; Function Attrs: uwtable
define void @"_ZN4core3ptr512drop_in_place$LT$alloc..vec..Vec$LT$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$GT$..extend_trusted$LT$core..iter..adapters..map..Map$LT$core..array..iter..IntoIter$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$C$1_usize$GT$$C$$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$u20$as$u20$core..convert..Into$LT$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$GT$$GT$..into$GT$$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$17h699cb8543f4e6d69E"(ptr align 8 %_1) unnamed_addr #1 {
start:
; call core::ptr::drop_in_place<alloc::vec::set_len_on_drop::SetLenOnDrop>
  call void @"_ZN4core3ptr62drop_in_place$LT$alloc..vec..set_len_on_drop..SetLenOnDrop$GT$17h000c414ff5ebd112E"(ptr align 8 %_1)
  ret void
}

; core::ptr::drop_in_place<&core::option::Option<u64>>
; Function Attrs: inlinehint uwtable
define hidden void @"_ZN4core3ptr56drop_in_place$LT$$RF$core..option..Option$LT$u64$GT$$GT$17h2b462ef8c2c66d16E"(ptr align 8 %_1) unnamed_addr #0 {
start:
  ret void
}

; core::ptr::drop_in_place<&misanthropic::client::AnthropicError>
; Function Attrs: inlinehint uwtable
define hidden void @"_ZN4core3ptr61drop_in_place$LT$$RF$misanthropic..client..AnthropicError$GT$17h0bffdc1506c8a304E"(ptr align 8 %_1) unnamed_addr #0 {
start:
  ret void
}

; core::ptr::drop_in_place<core::iter::traits::iterator::Iterator::for_each::call<misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>,alloc::vec::Vec<misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>>::extend_trusted<core::iter::adapters::map::Map<core::array::iter::IntoIter<(misanthropic::prompt::message::Role,&str),1_usize>,<(misanthropic::prompt::message::Role,&str) as core::convert::Into<misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>>>::into>>::{{closure}}>::{{closure}}>
; Function Attrs: uwtable
define void @"_ZN4core3ptr691drop_in_place$LT$core..iter..traits..iterator..Iterator..for_each..call$LT$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$C$alloc..vec..Vec$LT$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$GT$..extend_trusted$LT$core..iter..adapters..map..Map$LT$core..array..iter..IntoIter$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$C$1_usize$GT$$C$$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$u20$as$u20$core..convert..Into$LT$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$GT$$GT$..into$GT$$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$17hc82beb9dbfa87dfdE"(ptr align 8 %_1) unnamed_addr #1 {
start:
; call core::ptr::drop_in_place<alloc::vec::Vec<misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>>::extend_trusted<core::iter::adapters::map::Map<core::array::iter::IntoIter<(misanthropic::prompt::message::Role,&str),1_usize>,<(misanthropic::prompt::message::Role,&str) as core::convert::Into<misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>>>::into>>::{{closure}}>
  call void @"_ZN4core3ptr512drop_in_place$LT$alloc..vec..Vec$LT$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$GT$..extend_trusted$LT$core..iter..adapters..map..Map$LT$core..array..iter..IntoIter$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$C$1_usize$GT$$C$$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$u20$as$u20$core..convert..Into$LT$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$GT$$GT$..into$GT$$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$17h699cb8543f4e6d69E"(ptr align 8 %_1)
  ret void
}

; core::ptr::drop_in_place<&alloc::vec::Vec<alloc::string::String>>
; Function Attrs: inlinehint uwtable
define hidden void @"_ZN4core3ptr69drop_in_place$LT$$RF$alloc..vec..Vec$LT$alloc..string..String$GT$$GT$17h2a8699ae3ba0ab7aE"(ptr align 8 %_1) unnamed_addr #0 {
start:
  ret void
}

; core::ptr::drop_in_place<misanthropic::key::unencrypted::InvalidKeyLength>
; Function Attrs: inlinehint uwtable
define hidden void @"_ZN4core3ptr69drop_in_place$LT$misanthropic..key..unencrypted..InvalidKeyLength$GT$17hb8dd3ff5b2b4b194E"(ptr align 8 %_1) unnamed_addr #0 {
start:
  ret void
}

; core::ptr::drop_in_place<core::option::Option<core::num::nonzero::NonZero<u16>>>
; Function Attrs: inlinehint uwtable
define hidden void @"_ZN4core3ptr87drop_in_place$LT$core..option..Option$LT$core..num..nonzero..NonZero$LT$u16$GT$$GT$$GT$17h42f9e2ecbca44bf6E"(ptr align 2 %_1) unnamed_addr #0 {
start:
  ret void
}

; core::ptr::non_null::NonNull<T>::new_unchecked::precondition_check
; Function Attrs: inlinehint nounwind uwtable
define hidden void @"_ZN4core3ptr8non_null16NonNull$LT$T$GT$13new_unchecked18precondition_check17hdda848a7e15288faE"(ptr %ptr) unnamed_addr #2 {
start:
  %_3 = ptrtoint ptr %ptr to i64
  %0 = icmp eq i64 %_3, 0
  br i1 %0, label %bb1, label %bb2

bb1:                                              ; preds = %start
; call core::panicking::panic_nounwind
  call void @_ZN4core9panicking14panic_nounwind17hb115782c8cb05dd0E(ptr align 1 @alloc_560a59ed819b9d9a5841f6e731c4c8e5, i64 210) #15
  unreachable

bb2:                                              ; preds = %start
  ret void
}

; core::ptr::drop_in_place<alloc::sync::Arc<core::option::Option<alloc::string::String>>>
; Function Attrs: uwtable
define void @"_ZN4core3ptr94drop_in_place$LT$alloc..sync..Arc$LT$core..option..Option$LT$alloc..string..String$GT$$GT$$GT$17hd380e56ac09759d7E"(ptr align 8 %_1) unnamed_addr #1 {
start:
; call <alloc::sync::Arc<T,A> as core::ops::drop::Drop>::drop
  call void @"_ZN71_$LT$alloc..sync..Arc$LT$T$C$A$GT$$u20$as$u20$core..ops..drop..Drop$GT$4drop17h871fbda61cb6d929E"(ptr align 8 %_1)
  ret void
}

; core::hint::assert_unchecked::precondition_check
; Function Attrs: inlinehint nounwind uwtable
define hidden void @_ZN4core4hint16assert_unchecked18precondition_check17he63daafc4d26dafdE(i1 zeroext %cond) unnamed_addr #2 {
start:
  br i1 %cond, label %bb2, label %bb1

bb1:                                              ; preds = %start
; call core::panicking::panic_nounwind
  call void @_ZN4core9panicking14panic_nounwind17hb115782c8cb05dd0E(ptr align 1 @alloc_64e308ef4babfeb8b6220184de794a17, i64 221) #15
  unreachable

bb2:                                              ; preds = %start
  ret void
}

; core::iter::traits::iterator::Iterator::map
; Function Attrs: inlinehint uwtable
define void @_ZN4core4iter6traits8iterator8Iterator3map17h78a1367dc208b4c1E(ptr sret([40 x i8]) align 8 %_0, ptr align 8 %self) unnamed_addr #0 {
start:
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_0, ptr align 8 %self, i64 40, i1 false)
  ret void
}

; core::iter::traits::iterator::Iterator::collect
; Function Attrs: inlinehint uwtable
define void @_ZN4core4iter6traits8iterator8Iterator7collect17h62aa1b65085a8056E(ptr sret([24 x i8]) align 8 %_0, ptr align 8 %self) unnamed_addr #0 personality ptr @__CxxFrameHandler3 {
start:
  %_6 = alloca [40 x i8], align 8
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_6, ptr align 8 %self, i64 40, i1 false)
; invoke <alloc::vec::Vec<T> as core::iter::traits::collect::FromIterator<T>>::from_iter
  invoke void @"_ZN95_$LT$alloc..vec..Vec$LT$T$GT$$u20$as$u20$core..iter..traits..collect..FromIterator$LT$T$GT$$GT$9from_iter17hc11902cdaf446d82E"(ptr sret([24 x i8]) align 8 %_0, ptr align 8 %_6, ptr align 8 @alloc_6c46f8590da398a638f194d8c62f4d95)
          to label %bb1 unwind label %funclet_bb4

bb4:                                              ; preds = %funclet_bb4
  br label %bb2

funclet_bb4:                                      ; preds = %start
  %cleanuppad = cleanuppad within none []
  br label %bb4

bb1:                                              ; preds = %start
  ret void

bb2:                                              ; preds = %bb3, %bb4
  cleanupret from %cleanuppad unwind to caller

bb3:                                              ; No predecessors!
; call core::ptr::drop_in_place<core::iter::adapters::map::Map<core::array::iter::IntoIter<(misanthropic::prompt::message::Role,&str),1_usize>,<(misanthropic::prompt::message::Role,&str) as core::convert::Into<misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>>>::into>>
  call void @"_ZN4core3ptr351drop_in_place$LT$core..iter..adapters..map..Map$LT$core..array..iter..IntoIter$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$C$1_usize$GT$$C$$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$u20$as$u20$core..convert..Into$LT$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$GT$$GT$..into$GT$$GT$17h290ac583dfbf459aE"(ptr align 8 %self) #17 [ "funclet"(token %cleanuppad) ]
  br label %bb2
}

; core::iter::traits::iterator::Iterator::for_each
; Function Attrs: inlinehint uwtable
define void @_ZN4core4iter6traits8iterator8Iterator8for_each17ha24c1bd082a40d51E(ptr align 8 %self, ptr align 8 %f) unnamed_addr #0 {
start:
  %_4 = alloca [24 x i8], align 8
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_4, ptr align 8 %f, i64 24, i1 false)
; call <core::iter::adapters::map::Map<I,F> as core::iter::traits::iterator::Iterator>::fold
  call void @"_ZN102_$LT$core..iter..adapters..map..Map$LT$I$C$F$GT$$u20$as$u20$core..iter..traits..iterator..Iterator$GT$4fold17hd8747bbf6b8dbf20E"(ptr align 8 %self, ptr align 8 %_4)
  ret void
}

; core::iter::traits::iterator::Iterator::for_each::call::{{closure}}
; Function Attrs: inlinehint uwtable
define void @"_ZN4core4iter6traits8iterator8Iterator8for_each4call28_$u7b$$u7b$closure$u7d$$u7d$17hb1a9c46ea897a305E"(ptr align 8 %_1, ptr align 8 %item) unnamed_addr #0 {
start:
  %_5 = alloca [32 x i8], align 8
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_5, ptr align 8 %item, i64 32, i1 false)
; call alloc::vec::Vec<T,A>::extend_trusted::{{closure}}
  call void @"_ZN5alloc3vec16Vec$LT$T$C$A$GT$14extend_trusted28_$u7b$$u7b$closure$u7d$$u7d$17h4261e8453833729cE"(ptr align 8 %_1, ptr align 8 %_5)
  ret void
}

; core::iter::adapters::map::map_fold::{{closure}}
; Function Attrs: inlinehint uwtable
define void @"_ZN4core4iter8adapters3map8map_fold28_$u7b$$u7b$closure$u7d$$u7d$17hb4ea91fb1768858dE"(ptr align 8 %_1, ptr align 8 %elt) unnamed_addr #0 personality ptr @__CxxFrameHandler3 {
start:
  %_10 = alloca [1 x i8], align 1
  %_9 = alloca [24 x i8], align 8
  %_7 = alloca [32 x i8], align 8
  %_5 = alloca [32 x i8], align 8
  store i8 1, ptr %_10, align 1
  %_8 = getelementptr inbounds i8, ptr %_1, i64 24
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_9, ptr align 8 %elt, i64 24, i1 false)
; invoke core::ops::function::FnMut::call_mut
  invoke void @_ZN4core3ops8function5FnMut8call_mut17hc36b141d03e00966E(ptr sret([32 x i8]) align 8 %_7, ptr align 1 %_8, ptr align 8 %_9)
          to label %bb1 unwind label %funclet_bb5

bb5:                                              ; preds = %funclet_bb5
  %0 = load i8, ptr %_10, align 1
  %1 = trunc nuw i8 %0 to i1
  br i1 %1, label %bb4, label %bb3

funclet_bb5:                                      ; preds = %bb1, %start
  %cleanuppad = cleanuppad within none []
  br label %bb5

bb1:                                              ; preds = %start
  store i8 0, ptr %_10, align 1
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_5, ptr align 8 %_7, i64 32, i1 false)
; invoke core::iter::traits::iterator::Iterator::for_each::call::{{closure}}
  invoke void @"_ZN4core4iter6traits8iterator8Iterator8for_each4call28_$u7b$$u7b$closure$u7d$$u7d$17hb1a9c46ea897a305E"(ptr align 8 %_1, ptr align 8 %_5)
          to label %bb2 unwind label %funclet_bb5

bb2:                                              ; preds = %bb1
  ret void

bb3:                                              ; preds = %bb4, %bb5
  cleanupret from %cleanuppad unwind to caller

bb4:                                              ; preds = %bb5
  br label %bb3
}

; core::alloc::layout::Layout::from_size_align_unchecked::precondition_check
; Function Attrs: inlinehint nounwind uwtable
define hidden void @_ZN4core5alloc6layout6Layout25from_size_align_unchecked18precondition_check17h57cfff5f5b8f7ed3E(i64 %size, i64 %align) unnamed_addr #2 personality ptr @__CxxFrameHandler3 {
start:
; invoke core::alloc::layout::Layout::is_size_align_valid
  %_3 = invoke zeroext i1 @_ZN4core5alloc6layout6Layout19is_size_align_valid17hc4a33d0890086caaE(i64 %size, i64 %align)
          to label %bb1 unwind label %cs_terminate

cs_terminate:                                     ; preds = %start
  %catchswitch = catchswitch within none [label %cp_terminate] unwind to caller

cp_terminate:                                     ; preds = %cs_terminate
  %catchpad = catchpad within %catchswitch [ptr null, i32 64, ptr null]
; call core::panicking::panic_cannot_unwind
  call void @_ZN4core9panicking19panic_cannot_unwind17h8a970db44b3fe0a2E() #19 [ "funclet"(token %catchpad) ]
  unreachable

bb1:                                              ; preds = %start
  br i1 %_3, label %bb2, label %bb3

bb3:                                              ; preds = %bb1
; call core::panicking::panic_nounwind
  call void @_ZN4core9panicking14panic_nounwind17hb115782c8cb05dd0E(ptr align 1 @alloc_1be5ea12ba708d9a11b6e93a7d387a75, i64 281) #15
  unreachable

bb2:                                              ; preds = %bb1
  ret void
}

; core::array::iter::iter_inner::PolymorphicIter<[core::mem::maybe_uninit::MaybeUninit<T>]>::try_fold::{{closure}}
; Function Attrs: inlinehint uwtable
define void @"_ZN4core5array4iter10iter_inner78PolymorphicIter$LT$$u5b$core..mem..maybe_uninit..MaybeUninit$LT$T$GT$$u5d$$GT$8try_fold28_$u7b$$u7b$closure$u7d$$u7d$17h8a7c2865f6b886e8E"(ptr align 8 %_1, i64 %idx) unnamed_addr #0 {
start:
  %_6 = alloca [24 x i8], align 8
  %elem = alloca [24 x i8], align 8
  %self.0 = load ptr, ptr %_1, align 8
  %0 = getelementptr inbounds i8, ptr %_1, i64 8
  %self.1 = load i64, ptr %0, align 8
  br label %bb2

bb2:                                              ; preds = %start
; call <usize as core::slice::index::SliceIndex<[T]>>::get_unchecked::precondition_check
  call void @"_ZN75_$LT$usize$u20$as$u20$core..slice..index..SliceIndex$LT$$u5b$T$u5d$$GT$$GT$13get_unchecked18precondition_check17h710e408a1265e886E"(i64 %idx, i64 %self.1) #18
  br label %bb4

bb4:                                              ; preds = %bb2
  %_12 = icmp ult i64 %idx, %self.1
  %self = getelementptr inbounds nuw %"core::mem::maybe_uninit::MaybeUninit<(misanthropic::prompt::message::Role, &str)>", ptr %self.0, i64 %idx
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %elem, ptr align 8 %self, i64 24, i1 false)
  %_5 = getelementptr inbounds i8, ptr %_1, i64 16
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_6, ptr align 8 %elem, i64 24, i1 false)
; call core::ops::try_trait::NeverShortCircuit<T>::wrap_mut_2::{{closure}}
  call void @"_ZN4core3ops9try_trait26NeverShortCircuit$LT$T$GT$10wrap_mut_228_$u7b$$u7b$closure$u7d$$u7d$17h49c81d74a5bb8055E"(ptr align 8 %_5, ptr align 8 %_6)
  ret void
}

; core::array::iter::<impl core::iter::traits::collect::IntoIterator for [T; N]>::into_iter
; Function Attrs: inlinehint uwtable
define void @"_ZN4core5array4iter94_$LT$impl$u20$core..iter..traits..collect..IntoIterator$u20$for$u20$$u5b$T$u3b$$u20$N$u5d$$GT$9into_iter17ha048ccdd5e2e08c3E"(ptr sret([40 x i8]) align 8 %_0, ptr align 8 %self) unnamed_addr #0 {
start:
  %_3 = alloca [40 x i8], align 8
  %_2 = alloca [24 x i8], align 8
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_2, ptr align 8 %self, i64 24, i1 false)
  store i64 0, ptr %_3, align 8
  %0 = getelementptr inbounds i8, ptr %_3, i64 8
  store i64 1, ptr %0, align 8
  %1 = getelementptr inbounds i8, ptr %_3, i64 16
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %1, ptr align 8 %_2, i64 24, i1 false)
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_0, ptr align 8 %_3, i64 40, i1 false)
  ret void
}

; core::slice::raw::from_raw_parts::precondition_check
; Function Attrs: inlinehint nounwind uwtable
define hidden void @_ZN4core5slice3raw14from_raw_parts18precondition_check17h8dc0b7a946410a15E(ptr %data, i64 %size, i64 %align, i64 %len) unnamed_addr #2 personality ptr @__CxxFrameHandler3 {
start:
  %0 = alloca [4 x i8], align 4
  %max_len = alloca [8 x i8], align 8
  %_11 = alloca [48 x i8], align 8
  %1 = call i64 @llvm.ctpop.i64(i64 %align)
  %2 = trunc i64 %1 to i32
  store i32 %2, ptr %0, align 4
  %_15 = load i32, ptr %0, align 4
  %3 = icmp eq i32 %_15, 1
  br i1 %3, label %bb8, label %bb9

bb8:                                              ; preds = %start
  %_13 = ptrtoint ptr %data to i64
  %_14 = sub i64 %align, 1
  %_12 = and i64 %_13, %_14
  %4 = icmp eq i64 %_12, 0
  br i1 %4, label %bb6, label %bb7

bb9:                                              ; preds = %start
  store ptr @alloc_e92e94d0ff530782b571cfd99ec66aef, ptr %_11, align 8
  %5 = getelementptr inbounds i8, ptr %_11, i64 8
  store i64 1, ptr %5, align 8
  %6 = load ptr, ptr @anon.9bb7cee0307838987e4b4b15e8b33297.0, align 8
  %7 = load i64, ptr getelementptr inbounds (i8, ptr @anon.9bb7cee0307838987e4b4b15e8b33297.0, i64 8), align 8
  %8 = getelementptr inbounds i8, ptr %_11, i64 32
  store ptr %6, ptr %8, align 8
  %9 = getelementptr inbounds i8, ptr %8, i64 8
  store i64 %7, ptr %9, align 8
  %10 = getelementptr inbounds i8, ptr %_11, i64 16
  store ptr inttoptr (i64 8 to ptr), ptr %10, align 8
  %11 = getelementptr inbounds i8, ptr %10, i64 8
  store i64 0, ptr %11, align 8
; invoke core::panicking::panic_fmt
  invoke void @_ZN4core9panicking9panic_fmt17h6b7e0a7dad869f5aE(ptr align 8 %_11, ptr align 8 @alloc_d5565c3c200d27d008540d6a6ddd052a) #16
          to label %unreachable unwind label %cs_terminate

bb6:                                              ; preds = %bb8
  %_9 = icmp eq i64 %_13, 0
  %_5 = xor i1 %_9, true
  br i1 %_5, label %bb1, label %bb4

bb7:                                              ; preds = %bb8
  br label %bb4

bb4:                                              ; preds = %bb7, %bb6
  br label %bb5

bb1:                                              ; preds = %bb6
  %_19 = icmp eq i64 %size, 0
  %12 = icmp eq i64 %size, 0
  br i1 %12, label %bb11, label %bb12

bb11:                                             ; preds = %bb1
  store i64 -1, ptr %max_len, align 8
  br label %bb14

bb12:                                             ; preds = %bb1
  br i1 %_19, label %panic, label %bb13

bb14:                                             ; preds = %bb13, %bb11
  %_20 = load i64, ptr %max_len, align 8
  %_7 = icmp ule i64 %len, %_20
  br i1 %_7, label %bb2, label %bb3

bb13:                                             ; preds = %bb12
  %13 = udiv i64 9223372036854775807, %size
  store i64 %13, ptr %max_len, align 8
  br label %bb14

panic:                                            ; preds = %bb12
; invoke core::panicking::panic_const::panic_const_div_by_zero
  invoke void @_ZN4core9panicking11panic_const23panic_const_div_by_zero17h67a3eed2454b1972E(ptr align 8 @alloc_413737a8117e59d7685b5a9a1a04e06a) #16
          to label %unreachable unwind label %cs_terminate

cs_terminate:                                     ; preds = %bb9, %panic
  %catchswitch = catchswitch within none [label %cp_terminate] unwind to caller

cp_terminate:                                     ; preds = %cs_terminate
  %catchpad = catchpad within %catchswitch [ptr null, i32 64, ptr null]
; call core::panicking::panic_cannot_unwind
  call void @_ZN4core9panicking19panic_cannot_unwind17h8a970db44b3fe0a2E() #19 [ "funclet"(token %catchpad) ]
  unreachable

unreachable:                                      ; preds = %bb9, %panic
  unreachable

bb3:                                              ; preds = %bb14
  br label %bb5

bb2:                                              ; preds = %bb14
  ret void

bb5:                                              ; preds = %bb4, %bb3
; call core::panicking::panic_nounwind
  call void @_ZN4core9panicking14panic_nounwind17hb115782c8cb05dd0E(ptr align 1 @alloc_a28e8c8fd5088943a8b5d44af697ff83, i64 279) #15
  unreachable
}

; core::result::Result<T,E>::unwrap
; Function Attrs: alwaysinline uwtable
define void @"_ZN4core6result19Result$LT$T$C$E$GT$6unwrap17h384dbd13302b37a3E"(ptr sret([360 x i8]) align 8 %t, ptr align 8 %self, ptr align 8 %0) unnamed_addr #3 personality ptr @__CxxFrameHandler3 {
start:
  %e = alloca [48 x i8], align 8
  %1 = load i64, ptr %self, align 8
  %2 = icmp eq i64 %1, 18
  %_2 = select i1 %2, i64 1, i64 0
  %3 = trunc nuw i64 %_2 to i1
  br i1 %3, label %bb2, label %bb3

bb2:                                              ; preds = %start
  %4 = getelementptr inbounds i8, ptr %self, i64 8
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %e, ptr align 8 %4, i64 48, i1 false)
; invoke core::result::unwrap_failed
  invoke void @_ZN4core6result13unwrap_failed17h70751bb42e9051bdE(ptr align 1 @alloc_00ae4b301f7fab8ac9617c03fcbd7274, i64 43, ptr align 1 %e, ptr align 8 @vtable.0, ptr align 8 %0) #16
          to label %unreachable unwind label %funclet_bb4

bb3:                                              ; preds = %start
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %t, ptr align 8 %self, i64 360, i1 false)
  ret void

bb4:                                              ; preds = %funclet_bb4
; call core::ptr::drop_in_place<misanthropic::client::Error>
  call void @"_ZN4core3ptr48drop_in_place$LT$misanthropic..client..Error$GT$17h0315295c7eac22e8E"(ptr align 8 %e) #17 [ "funclet"(token %cleanuppad) ]
  cleanupret from %cleanuppad unwind to caller

funclet_bb4:                                      ; preds = %bb2
  %cleanuppad = cleanuppad within none []
  br label %bb4

unreachable:                                      ; preds = %bb2
  unreachable

bb1:                                              ; No predecessors!
  unreachable
}

; core::result::Result<T,E>::unwrap
; Function Attrs: alwaysinline uwtable
define void @"_ZN4core6result19Result$LT$T$C$E$GT$6unwrap17h50de7294f50a9585E"(ptr sret([384 x i8]) align 8 %t, ptr align 8 %self, ptr align 8 %0) unnamed_addr #3 personality ptr @__CxxFrameHandler3 {
start:
  %e = alloca [64 x i8], align 8
  %1 = load i64, ptr %self, align 8
  %2 = icmp eq i64 %1, -9223372036854775808
  %_2 = select i1 %2, i64 1, i64 0
  %3 = trunc nuw i64 %_2 to i1
  br i1 %3, label %bb2, label %bb3

bb2:                                              ; preds = %start
  %4 = getelementptr inbounds i8, ptr %self, i64 8
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %e, ptr align 8 %4, i64 64, i1 false)
; invoke core::result::unwrap_failed
  invoke void @_ZN4core6result13unwrap_failed17h70751bb42e9051bdE(ptr align 1 @alloc_00ae4b301f7fab8ac9617c03fcbd7274, i64 43, ptr align 1 %e, ptr align 8 @vtable.1, ptr align 8 %0) #16
          to label %unreachable unwind label %funclet_bb4

bb3:                                              ; preds = %start
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %t, ptr align 8 %self, i64 384, i1 false)
  ret void

bb4:                                              ; preds = %funclet_bb4
; call core::ptr::drop_in_place<misanthropic::prompt::TurnOrderError>
  call void @"_ZN4core3ptr57drop_in_place$LT$misanthropic..prompt..TurnOrderError$GT$17h7350f3462e7bc41cE"(ptr align 8 %e) #17 [ "funclet"(token %cleanuppad) ]
  cleanupret from %cleanuppad unwind to caller

funclet_bb4:                                      ; preds = %bb2
  %cleanuppad = cleanuppad within none []
  br label %bb4

unreachable:                                      ; preds = %bb2
  unreachable

bb1:                                              ; No predecessors!
  unreachable
}

; core::result::Result<T,E>::unwrap
; Function Attrs: alwaysinline uwtable
define void @"_ZN4core6result19Result$LT$T$C$E$GT$6unwrap17h5e5bc3400780928bE"(ptr sret([56 x i8]) align 8 %t, ptr align 8 %self, ptr align 8 %0) unnamed_addr #3 personality ptr @__CxxFrameHandler3 {
start:
  %e = alloca [8 x i8], align 8
  %1 = load ptr, ptr %self, align 8
  %2 = ptrtoint ptr %1 to i64
  %3 = icmp eq i64 %2, 0
  %_2 = select i1 %3, i64 1, i64 0
  %4 = trunc nuw i64 %_2 to i1
  br i1 %4, label %bb2, label %bb3

bb2:                                              ; preds = %start
  %5 = getelementptr inbounds i8, ptr %self, i64 8
  %6 = load i64, ptr %5, align 8
  store i64 %6, ptr %e, align 8
; invoke core::result::unwrap_failed
  invoke void @_ZN4core6result13unwrap_failed17h70751bb42e9051bdE(ptr align 1 @alloc_00ae4b301f7fab8ac9617c03fcbd7274, i64 43, ptr align 1 %e, ptr align 8 @vtable.2, ptr align 8 %0) #16
          to label %unreachable unwind label %funclet_bb4

bb3:                                              ; preds = %start
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %t, ptr align 8 %self, i64 56, i1 false)
  ret void

bb4:                                              ; preds = %funclet_bb4
  cleanupret from %cleanuppad unwind to caller

funclet_bb4:                                      ; preds = %bb2
  %cleanuppad = cleanuppad within none []
  br label %bb4

unreachable:                                      ; preds = %bb2
  unreachable

bb1:                                              ; No predecessors!
  unreachable
}

; core::result::Result<T,E>::unwrap
; Function Attrs: alwaysinline uwtable
define void @"_ZN4core6result19Result$LT$T$C$E$GT$6unwrap17ha3da71368a295819E"(ptr sret([288 x i8]) align 8 %t, ptr align 8 %self, ptr align 8 %0) unnamed_addr #3 personality ptr @__CxxFrameHandler3 {
start:
  %e = alloca [48 x i8], align 8
  %1 = load i64, ptr %self, align 8
  %2 = icmp eq i64 %1, 2
  %_2 = select i1 %2, i64 1, i64 0
  %3 = trunc nuw i64 %_2 to i1
  br i1 %3, label %bb2, label %bb3

bb2:                                              ; preds = %start
  %4 = getelementptr inbounds i8, ptr %self, i64 8
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %e, ptr align 8 %4, i64 48, i1 false)
; invoke core::result::unwrap_failed
  invoke void @_ZN4core6result13unwrap_failed17h70751bb42e9051bdE(ptr align 1 @alloc_00ae4b301f7fab8ac9617c03fcbd7274, i64 43, ptr align 1 %e, ptr align 8 @vtable.0, ptr align 8 %0) #16
          to label %unreachable unwind label %funclet_bb4

bb3:                                              ; preds = %start
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %t, ptr align 8 %self, i64 288, i1 false)
  ret void

bb4:                                              ; preds = %funclet_bb4
; call core::ptr::drop_in_place<misanthropic::client::Error>
  call void @"_ZN4core3ptr48drop_in_place$LT$misanthropic..client..Error$GT$17h0315295c7eac22e8E"(ptr align 8 %e) #17 [ "funclet"(token %cleanuppad) ]
  cleanupret from %cleanuppad unwind to caller

funclet_bb4:                                      ; preds = %bb2
  %cleanuppad = cleanuppad within none []
  br label %bb4

unreachable:                                      ; preds = %bb2
  unreachable

bb1:                                              ; No predecessors!
  unreachable
}

; <T as core::convert::From<T>>::from
; Function Attrs: alwaysinline uwtable
define void @"_ZN50_$LT$T$u20$as$u20$core..convert..From$LT$T$GT$$GT$4from17h13f2a25bc0eaa362E"(ptr sret([64 x i8]) align 8 %_0, ptr align 8 %t) unnamed_addr #3 {
start:
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_0, ptr align 8 %t, i64 64, i1 false)
  ret void
}

; <T as core::convert::From<T>>::from
; Function Attrs: alwaysinline uwtable
define void @"_ZN50_$LT$T$u20$as$u20$core..convert..From$LT$T$GT$$GT$4from17h4db2ab0105e6bc36E"(ptr sret([48 x i8]) align 8 %_0, ptr align 8 %t) unnamed_addr #3 {
start:
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_0, ptr align 8 %t, i64 48, i1 false)
  ret void
}

; <T as core::convert::From<T>>::from
; Function Attrs: alwaysinline uwtable
define i64 @"_ZN50_$LT$T$u20$as$u20$core..convert..From$LT$T$GT$$GT$4from17hf02772ce88595211E"(i64 %t) unnamed_addr #3 {
start:
  ret i64 %t
}

; <T as core::convert::Into<U>>::into
; Function Attrs: inlinehint uwtable
define void @"_ZN50_$LT$T$u20$as$u20$core..convert..Into$LT$U$GT$$GT$4into17h503729507de9c474E"(ptr sret([24 x i8]) align 8 %_0, ptr align 1 %self.0, i64 %self.1, ptr align 8 %0) unnamed_addr #0 {
start:
; call <misanthropic::prompt::message::Content as core::convert::From<T>>::from
  call void @"_ZN87_$LT$misanthropic..prompt..message..Content$u20$as$u20$core..convert..From$LT$T$GT$$GT$4from17h282ef9696aa6f308E"(ptr sret([24 x i8]) align 8 %_0, ptr align 1 %self.0, i64 %self.1)
  ret void
}

; <T as core::convert::Into<U>>::into
; Function Attrs: inlinehint uwtable
define void @"_ZN50_$LT$T$u20$as$u20$core..convert..Into$LT$U$GT$$GT$4into17hbd967f24024c959cE"(ptr sret([32 x i8]) align 8 %_0, ptr align 8 %self, ptr align 8 %0) unnamed_addr #0 {
start:
; call <misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role> as core::convert::From<(misanthropic::prompt::message::Role,T)>>::from
  call void @"_ZN180_$LT$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$u20$as$u20$core..convert..From$LT$$LP$misanthropic..prompt..message..Role$C$T$RP$$GT$$GT$4from17h0ff67a9cccd0d117E"(ptr sret([32 x i8]) align 8 %_0, ptr align 8 %self)
  ret void
}

; <T as core::convert::TryInto<U>>::try_into
; Function Attrs: inlinehint uwtable
define void @"_ZN53_$LT$T$u20$as$u20$core..convert..TryInto$LT$U$GT$$GT$8try_into17hb9d123282d886cc6E"(ptr sret([112 x i8]) align 8 %_0, ptr align 8 %self) unnamed_addr #0 {
start:
; call <misanthropic::key::unencrypted::Key as core::convert::TryFrom<alloc::string::String>>::try_from
  call void @"_ZN107_$LT$misanthropic..key..unencrypted..Key$u20$as$u20$core..convert..TryFrom$LT$alloc..string..String$GT$$GT$8try_from17he4808e8e9ebbcd65E"(ptr sret([112 x i8]) align 8 %_0, ptr align 8 %self)
  ret void
}

; <alloc::string::String as core::fmt::Debug>::fmt
; Function Attrs: inlinehint uwtable
define hidden zeroext i1 @"_ZN58_$LT$alloc..string..String$u20$as$u20$core..fmt..Debug$GT$3fmt17h6bdadfc155e851afE"(ptr align 8 %self, ptr align 8 %f) unnamed_addr #0 {
start:
  %0 = getelementptr inbounds i8, ptr %self, i64 8
  %_8 = load ptr, ptr %0, align 8
  %1 = getelementptr inbounds i8, ptr %self, i64 16
  %len = load i64, ptr %1, align 8
  br label %bb2

bb2:                                              ; preds = %start
; call core::slice::raw::from_raw_parts::precondition_check
  call void @_ZN4core5slice3raw14from_raw_parts18precondition_check17h8dc0b7a946410a15E(ptr %_8, i64 1, i64 1, i64 %len) #18
  br label %bb4

bb4:                                              ; preds = %bb2
; call <str as core::fmt::Debug>::fmt
  %_0 = call zeroext i1 @"_ZN40_$LT$str$u20$as$u20$core..fmt..Debug$GT$3fmt17h03321ffdd769ea00E"(ptr align 1 %_8, i64 %len, ptr align 8 %f)
  ret i1 %_0
}

; <F as core::future::into_future::IntoFuture>::into_future
; Function Attrs: uwtable
define void @"_ZN59_$LT$F$u20$as$u20$core..future..into_future..IntoFuture$GT$11into_future17h52a589b0e5dcff10E"(ptr sret([1192 x i8]) align 8 %_0, ptr align 8 %self) unnamed_addr #1 {
start:
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_0, ptr align 8 %self, i64 1192, i1 false)
  ret void
}

; alloc::vec::Vec<T,A>::extend_trusted
; Function Attrs: uwtable
define void @"_ZN5alloc3vec16Vec$LT$T$C$A$GT$14extend_trusted17h462e43ac2a13841cE"(ptr align 8 %self, ptr align 8 %iterator, ptr align 8 %0) unnamed_addr #1 personality ptr @__CxxFrameHandler3 {
start:
  %_22 = alloca [1 x i8], align 1
  %_21 = alloca [48 x i8], align 8
  %_19 = alloca [24 x i8], align 8
  %_18 = alloca [40 x i8], align 8
  %_5 = alloca [24 x i8], align 8
  %high = alloca [16 x i8], align 8
  store i8 1, ptr %_22, align 1
; invoke <core::iter::adapters::map::Map<I,F> as core::iter::traits::iterator::Iterator>::size_hint
  invoke void @"_ZN102_$LT$core..iter..adapters..map..Map$LT$I$C$F$GT$$u20$as$u20$core..iter..traits..iterator..Iterator$GT$9size_hint17h66acc32d3e0bbd05E"(ptr sret([24 x i8]) align 8 %_5, ptr align 8 %iterator)
          to label %bb1 unwind label %funclet_bb8

bb8:                                              ; preds = %funclet_bb8
  %1 = load i8, ptr %_22, align 1
  %2 = trunc nuw i8 %1 to i1
  br i1 %2, label %bb7, label %bb6

funclet_bb8:                                      ; preds = %bb5, %bb3, %bb2, %start
  %cleanuppad = cleanuppad within none []
  br label %bb8

bb1:                                              ; preds = %start
  %low = load i64, ptr %_5, align 8
  %3 = getelementptr inbounds i8, ptr %_5, i64 8
  %4 = load i64, ptr %3, align 8
  %5 = getelementptr inbounds i8, ptr %3, i64 8
  %6 = load i64, ptr %5, align 8
  store i64 %4, ptr %high, align 8
  %7 = getelementptr inbounds i8, ptr %high, i64 8
  store i64 %6, ptr %7, align 8
  %_7 = load i64, ptr %high, align 8
  %8 = getelementptr inbounds i8, ptr %high, i64 8
  %9 = load i64, ptr %8, align 8
  %10 = trunc nuw i64 %_7 to i1
  br i1 %10, label %bb2, label %bb5

bb2:                                              ; preds = %bb1
  %11 = getelementptr inbounds i8, ptr %high, i64 8
  %additional = load i64, ptr %11, align 8
; invoke alloc::vec::Vec<T,A>::reserve
  invoke void @"_ZN5alloc3vec16Vec$LT$T$C$A$GT$7reserve17hf6e4c58c0e63f0ceE"(ptr align 8 %self, i64 %additional, ptr align 8 %0)
          to label %bb3 unwind label %funclet_bb8

bb5:                                              ; preds = %bb1
  store ptr @alloc_11d257f5ed6cc7fc38feaa801053bac6, ptr %_21, align 8
  %12 = getelementptr inbounds i8, ptr %_21, i64 8
  store i64 1, ptr %12, align 8
  %13 = load ptr, ptr @anon.9bb7cee0307838987e4b4b15e8b33297.0, align 8
  %14 = load i64, ptr getelementptr inbounds (i8, ptr @anon.9bb7cee0307838987e4b4b15e8b33297.0, i64 8), align 8
  %15 = getelementptr inbounds i8, ptr %_21, i64 32
  store ptr %13, ptr %15, align 8
  %16 = getelementptr inbounds i8, ptr %15, i64 8
  store i64 %14, ptr %16, align 8
  %17 = getelementptr inbounds i8, ptr %_21, i64 16
  store ptr inttoptr (i64 8 to ptr), ptr %17, align 8
  %18 = getelementptr inbounds i8, ptr %17, i64 8
  store i64 0, ptr %18, align 8
; invoke core::panicking::panic_fmt
  invoke void @_ZN4core9panicking9panic_fmt17h6b7e0a7dad869f5aE(ptr align 8 %_21, ptr align 8 %0) #16
          to label %unreachable unwind label %funclet_bb8

bb3:                                              ; preds = %bb2
  %19 = getelementptr inbounds i8, ptr %self, i64 8
  %_23 = load ptr, ptr %19, align 8
  %len = getelementptr inbounds i8, ptr %self, i64 16
  %_24 = load i64, ptr %len, align 8
  store i8 0, ptr %_22, align 1
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_18, ptr align 8 %iterator, i64 40, i1 false)
  %20 = getelementptr inbounds i8, ptr %_19, i64 16
  store ptr %_23, ptr %20, align 8
  store ptr %len, ptr %_19, align 8
  %21 = getelementptr inbounds i8, ptr %_19, i64 8
  store i64 %_24, ptr %21, align 8
; invoke core::iter::traits::iterator::Iterator::for_each
  invoke void @_ZN4core4iter6traits8iterator8Iterator8for_each17ha24c1bd082a40d51E(ptr align 8 %_18, ptr align 8 %_19)
          to label %bb4 unwind label %funclet_bb8

bb4:                                              ; preds = %bb3
  ret void

unreachable:                                      ; preds = %bb5
  unreachable

bb9:                                              ; No predecessors!
  unreachable

bb6:                                              ; preds = %bb7, %bb8
  cleanupret from %cleanuppad unwind to caller

bb7:                                              ; preds = %bb8
; call core::ptr::drop_in_place<core::iter::adapters::map::Map<core::array::iter::IntoIter<(misanthropic::prompt::message::Role,&str),1_usize>,<(misanthropic::prompt::message::Role,&str) as core::convert::Into<misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>>>::into>>
  call void @"_ZN4core3ptr351drop_in_place$LT$core..iter..adapters..map..Map$LT$core..array..iter..IntoIter$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$C$1_usize$GT$$C$$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$u20$as$u20$core..convert..Into$LT$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$GT$$GT$..into$GT$$GT$17h290ac583dfbf459aE"(ptr align 8 %iterator) #17 [ "funclet"(token %cleanuppad) ]
  br label %bb6
}

; alloc::vec::Vec<T,A>::extend_trusted::{{closure}}
; Function Attrs: inlinehint uwtable
define void @"_ZN5alloc3vec16Vec$LT$T$C$A$GT$14extend_trusted28_$u7b$$u7b$closure$u7d$$u7d$17h4261e8453833729cE"(ptr align 8 %_1, ptr align 8 %element) unnamed_addr #0 {
start:
  %0 = getelementptr inbounds i8, ptr %_1, i64 16
  %_4 = load ptr, ptr %0, align 8
  %1 = getelementptr inbounds i8, ptr %_1, i64 8
  %_5 = load i64, ptr %1, align 8
  %_3 = getelementptr inbounds nuw %"misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>", ptr %_4, i64 %_5
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_3, ptr align 8 %element, i64 32, i1 false)
  %2 = getelementptr inbounds i8, ptr %_1, i64 8
  %3 = getelementptr inbounds i8, ptr %_1, i64 8
  %4 = load i64, ptr %3, align 8
  %5 = add i64 %4, 1
  store i64 %5, ptr %2, align 8
  ret void
}

; alloc::vec::Vec<T,A>::reserve
; Function Attrs: uwtable
define void @"_ZN5alloc3vec16Vec$LT$T$C$A$GT$7reserve17hf6e4c58c0e63f0ceE"(ptr align 8 %self, i64 %additional, ptr align 8 %0) unnamed_addr #1 {
start:
  %self1 = alloca [8 x i8], align 8
  %elem_layout = alloca [16 x i8], align 8
  %1 = getelementptr inbounds i8, ptr %self, i64 16
  %len = load i64, ptr %1, align 8
  store i64 8, ptr %elem_layout, align 8
  %2 = getelementptr inbounds i8, ptr %elem_layout, i64 8
  store i64 32, ptr %2, align 8
  br label %bb6

bb6:                                              ; preds = %start
  %self2 = load i64, ptr %self, align 8
  store i64 %self2, ptr %self1, align 8
  br label %bb4

bb5:                                              ; No predecessors!
  store i64 -1, ptr %self1, align 8
  br label %bb4

bb4:                                              ; preds = %bb6, %bb5
  %3 = load i64, ptr %self1, align 8
  %_10 = sub i64 %3, %len
  %_7 = icmp ugt i64 %additional, %_10
  br i1 %_7, label %bb1, label %bb2

bb2:                                              ; preds = %bb4
  br label %bb3

bb1:                                              ; preds = %bb4
; call alloc::raw_vec::RawVecInner<A>::reserve::do_reserve_and_handle
  call void @"_ZN5alloc7raw_vec20RawVecInner$LT$A$GT$7reserve21do_reserve_and_handle17hc13a237b4d39ded0E"(ptr align 8 %self, i64 %len, i64 %additional, i64 8, i64 32)
  br label %bb3

bb3:                                              ; preds = %bb1, %bb2
  ret void
}

; alloc::sync::Arc<T,A>::drop_slow
; Function Attrs: noinline uwtable
define void @"_ZN5alloc4sync16Arc$LT$T$C$A$GT$9drop_slow17h5fab925c6c5d111eE"(ptr align 8 %self) unnamed_addr #4 personality ptr @__CxxFrameHandler3 {
start:
  %_weak = alloca [16 x i8], align 8
  %_3 = load ptr, ptr %self, align 8
  %_4 = getelementptr inbounds i8, ptr %self, i64 8
  store ptr %_3, ptr %_weak, align 8
  %0 = getelementptr inbounds i8, ptr %_weak, i64 8
  store ptr %_4, ptr %0, align 8
  %self1 = load ptr, ptr %self, align 8
  %_6 = getelementptr inbounds i8, ptr %self1, i64 16
; invoke core::ptr::drop_in_place<core::option::Option<alloc::string::String>>
  invoke void @"_ZN4core3ptr70drop_in_place$LT$core..option..Option$LT$alloc..string..String$GT$$GT$17hb91fbec02e242124E"(ptr align 8 %_6)
          to label %bb1 unwind label %funclet_bb3

bb3:                                              ; preds = %funclet_bb3
; call core::ptr::drop_in_place<alloc::sync::Weak<core::option::Option<alloc::string::String>,&alloc::alloc::Global>>
  call void @"_ZN4core3ptr122drop_in_place$LT$alloc..sync..Weak$LT$core..option..Option$LT$alloc..string..String$GT$$C$$RF$alloc..alloc..Global$GT$$GT$17h0fed26da7cd7816cE"(ptr align 8 %_weak) #17 [ "funclet"(token %cleanuppad) ]
  cleanupret from %cleanuppad unwind to caller

funclet_bb3:                                      ; preds = %start
  %cleanuppad = cleanuppad within none []
  br label %bb3

bb1:                                              ; preds = %start
; call core::ptr::drop_in_place<alloc::sync::Weak<core::option::Option<alloc::string::String>,&alloc::alloc::Global>>
  call void @"_ZN4core3ptr122drop_in_place$LT$alloc..sync..Weak$LT$core..option..Option$LT$alloc..string..String$GT$$C$$RF$alloc..alloc..Global$GT$$GT$17h0fed26da7cd7816cE"(ptr align 8 %_weak)
  ret void
}

; alloc::alloc::alloc_zeroed
; Function Attrs: inlinehint uwtable
define hidden ptr @_ZN5alloc5alloc12alloc_zeroed17hff2f84047de9e21aE(i64 %0, i64 %1) unnamed_addr #0 {
start:
  %2 = alloca [1 x i8], align 1
  %layout = alloca [16 x i8], align 8
  store i64 %0, ptr %layout, align 8
  %3 = getelementptr inbounds i8, ptr %layout, i64 8
  store i64 %1, ptr %3, align 8
  br label %bb3

bb3:                                              ; preds = %start
; call core::ptr::read_volatile::precondition_check
  call void @_ZN4core3ptr13read_volatile18precondition_check17h3c045cae23cc78bcE(ptr @__rust_no_alloc_shim_is_unstable, i64 1, i1 zeroext false) #18
  br label %bb5

bb5:                                              ; preds = %bb3
  %4 = load volatile i8, ptr @__rust_no_alloc_shim_is_unstable, align 1
  store i8 %4, ptr %2, align 1
  %_2 = load i8, ptr %2, align 1
  %5 = getelementptr inbounds i8, ptr %layout, i64 8
  %_3 = load i64, ptr %5, align 8
  %_10 = load i64, ptr %layout, align 8
  %_13 = icmp uge i64 %_10, 1
  %_14 = icmp ule i64 %_10, -9223372036854775808
  %_15 = and i1 %_13, %_14
; call __rustc::__rust_alloc_zeroed
  %_0 = call ptr @_RNvCs691rhTbG0Ee_7___rustc19___rust_alloc_zeroed(i64 %_3, i64 %_10) #18
  ret ptr %_0
}

; alloc::alloc::exchange_malloc
; Function Attrs: inlinehint uwtable
define hidden ptr @_ZN5alloc5alloc15exchange_malloc17h2cfa1ed50d4343f0E(i64 %size, i64 %align) unnamed_addr #0 {
start:
  %_4 = alloca [16 x i8], align 8
  br label %bb4

bb4:                                              ; preds = %start
; call core::alloc::layout::Layout::from_size_align_unchecked::precondition_check
  call void @_ZN4core5alloc6layout6Layout25from_size_align_unchecked18precondition_check17h57cfff5f5b8f7ed3E(i64 %size, i64 %align) #18
  br label %bb5

bb5:                                              ; preds = %bb4
; call alloc::alloc::Global::alloc_impl
  %0 = call { ptr, i64 } @_ZN5alloc5alloc6Global10alloc_impl17hc42878f954422bddE(ptr align 1 inttoptr (i64 1 to ptr), i64 %align, i64 %size, i1 zeroext false)
  %1 = extractvalue { ptr, i64 } %0, 0
  %2 = extractvalue { ptr, i64 } %0, 1
  store ptr %1, ptr %_4, align 8
  %3 = getelementptr inbounds i8, ptr %_4, i64 8
  store i64 %2, ptr %3, align 8
  %4 = load ptr, ptr %_4, align 8
  %5 = getelementptr inbounds i8, ptr %_4, i64 8
  %6 = load i64, ptr %5, align 8
  %7 = ptrtoint ptr %4 to i64
  %8 = icmp eq i64 %7, 0
  %_5 = select i1 %8, i64 1, i64 0
  %9 = trunc nuw i64 %_5 to i1
  br i1 %9, label %bb2, label %bb3

bb2:                                              ; preds = %bb5
; call alloc::alloc::handle_alloc_error
  call void @_ZN5alloc5alloc18handle_alloc_error17h5d20bbd2fe1a1ecaE(i64 %align, i64 %size) #16
  unreachable

bb3:                                              ; preds = %bb5
  %ptr.0 = load ptr, ptr %_4, align 8
  %10 = getelementptr inbounds i8, ptr %_4, i64 8
  %ptr.1 = load i64, ptr %10, align 8
  ret ptr %ptr.0

bb1:                                              ; No predecessors!
  unreachable
}

; alloc::alloc::alloc
; Function Attrs: inlinehint uwtable
define hidden ptr @_ZN5alloc5alloc5alloc17hab3aba50fd1a4836E(i64 %0, i64 %1) unnamed_addr #0 {
start:
  %2 = alloca [1 x i8], align 1
  %layout = alloca [16 x i8], align 8
  store i64 %0, ptr %layout, align 8
  %3 = getelementptr inbounds i8, ptr %layout, i64 8
  store i64 %1, ptr %3, align 8
  br label %bb3

bb3:                                              ; preds = %start
; call core::ptr::read_volatile::precondition_check
  call void @_ZN4core3ptr13read_volatile18precondition_check17h3c045cae23cc78bcE(ptr @__rust_no_alloc_shim_is_unstable, i64 1, i1 zeroext false) #18
  br label %bb5

bb5:                                              ; preds = %bb3
  %4 = load volatile i8, ptr @__rust_no_alloc_shim_is_unstable, align 1
  store i8 %4, ptr %2, align 1
  %_2 = load i8, ptr %2, align 1
  %5 = getelementptr inbounds i8, ptr %layout, i64 8
  %_3 = load i64, ptr %5, align 8
  %_10 = load i64, ptr %layout, align 8
  %_13 = icmp uge i64 %_10, 1
  %_14 = icmp ule i64 %_10, -9223372036854775808
  %_15 = and i1 %_13, %_14
; call __rustc::__rust_alloc
  %_0 = call ptr @_RNvCs691rhTbG0Ee_7___rustc12___rust_alloc(i64 %_3, i64 %_10) #18
  ret ptr %_0
}

; alloc::alloc::Global::alloc_impl
; Function Attrs: inlinehint uwtable
define hidden { ptr, i64 } @_ZN5alloc5alloc6Global10alloc_impl17hc42878f954422bddE(ptr align 1 %self, i64 %0, i64 %1, i1 zeroext %zeroed) unnamed_addr #0 {
start:
  %self2 = alloca [8 x i8], align 8
  %self1 = alloca [8 x i8], align 8
  %_10 = alloca [8 x i8], align 8
  %raw_ptr = alloca [8 x i8], align 8
  %_0 = alloca [16 x i8], align 8
  %layout = alloca [16 x i8], align 8
  store i64 %0, ptr %layout, align 8
  %2 = getelementptr inbounds i8, ptr %layout, i64 8
  store i64 %1, ptr %2, align 8
  %3 = getelementptr inbounds i8, ptr %layout, i64 8
  %size = load i64, ptr %3, align 8
  %4 = icmp eq i64 %size, 0
  br i1 %4, label %bb2, label %bb1

bb2:                                              ; preds = %start
  %_17 = load i64, ptr %layout, align 8
  %_18 = getelementptr i8, ptr null, i64 %_17
  %data = getelementptr i8, ptr null, i64 %_17
  br label %bb7

bb1:                                              ; preds = %start
  br i1 %zeroed, label %bb3, label %bb4

bb7:                                              ; preds = %bb2
  %_22 = getelementptr i8, ptr null, i64 %_17
; call core::ptr::non_null::NonNull<T>::new_unchecked::precondition_check
  call void @"_ZN4core3ptr8non_null16NonNull$LT$T$GT$13new_unchecked18precondition_check17hdda848a7e15288faE"(ptr %_22) #18
  br label %bb9

bb9:                                              ; preds = %bb7
  store ptr %data, ptr %_0, align 8
  %5 = getelementptr inbounds i8, ptr %_0, i64 8
  store i64 0, ptr %5, align 8
  br label %bb6

bb6:                                              ; preds = %bb17, %bb10, %bb9
  %6 = load ptr, ptr %_0, align 8
  %7 = getelementptr inbounds i8, ptr %_0, i64 8
  %8 = load i64, ptr %7, align 8
  %9 = insertvalue { ptr, i64 } poison, ptr %6, 0
  %10 = insertvalue { ptr, i64 } %9, i64 %8, 1
  ret { ptr, i64 } %10

bb4:                                              ; preds = %bb1
  %11 = load i64, ptr %layout, align 8
  %12 = getelementptr inbounds i8, ptr %layout, i64 8
  %13 = load i64, ptr %12, align 8
; call alloc::alloc::alloc
  %14 = call ptr @_ZN5alloc5alloc5alloc17hab3aba50fd1a4836E(i64 %11, i64 %13)
  store ptr %14, ptr %raw_ptr, align 8
  br label %bb5

bb3:                                              ; preds = %bb1
  %15 = load i64, ptr %layout, align 8
  %16 = getelementptr inbounds i8, ptr %layout, i64 8
  %17 = load i64, ptr %16, align 8
; call alloc::alloc::alloc_zeroed
  %18 = call ptr @_ZN5alloc5alloc12alloc_zeroed17hff2f84047de9e21aE(i64 %15, i64 %17)
  store ptr %18, ptr %raw_ptr, align 8
  br label %bb5

bb5:                                              ; preds = %bb3, %bb4
  %ptr = load ptr, ptr %raw_ptr, align 8
  %_27 = ptrtoint ptr %ptr to i64
  %19 = icmp eq i64 %_27, 0
  br i1 %19, label %bb10, label %bb11

bb10:                                             ; preds = %bb5
  store ptr null, ptr %self2, align 8
  store ptr null, ptr %self1, align 8
  %20 = load ptr, ptr @anon.9bb7cee0307838987e4b4b15e8b33297.0, align 8
  %21 = load i64, ptr getelementptr inbounds (i8, ptr @anon.9bb7cee0307838987e4b4b15e8b33297.0, i64 8), align 8
  store ptr %20, ptr %_0, align 8
  %22 = getelementptr inbounds i8, ptr %_0, i64 8
  store i64 %21, ptr %22, align 8
  br label %bb6

bb11:                                             ; preds = %bb5
  br label %bb12

bb12:                                             ; preds = %bb11
; call core::ptr::non_null::NonNull<T>::new_unchecked::precondition_check
  call void @"_ZN4core3ptr8non_null16NonNull$LT$T$GT$13new_unchecked18precondition_check17hdda848a7e15288faE"(ptr %ptr) #18
  br label %bb14

bb14:                                             ; preds = %bb12
  store ptr %ptr, ptr %self2, align 8
  %v = load ptr, ptr %self2, align 8
  store ptr %v, ptr %self1, align 8
  %v3 = load ptr, ptr %self1, align 8
  store ptr %v3, ptr %_10, align 8
  %ptr4 = load ptr, ptr %_10, align 8
  br label %bb15

bb15:                                             ; preds = %bb14
; call core::ptr::non_null::NonNull<T>::new_unchecked::precondition_check
  call void @"_ZN4core3ptr8non_null16NonNull$LT$T$GT$13new_unchecked18precondition_check17hdda848a7e15288faE"(ptr %ptr4) #18
  br label %bb17

bb17:                                             ; preds = %bb15
  store ptr %ptr4, ptr %_0, align 8
  %23 = getelementptr inbounds i8, ptr %_0, i64 8
  store i64 %size, ptr %23, align 8
  br label %bb6
}

; <I as core::iter::traits::collect::IntoIterator>::into_iter
; Function Attrs: inlinehint uwtable
define void @"_ZN63_$LT$I$u20$as$u20$core..iter..traits..collect..IntoIterator$GT$9into_iter17h3fc5d653af7a31f5E"(ptr sret([40 x i8]) align 8 %_0, ptr align 8 %self) unnamed_addr #0 {
start:
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_0, ptr align 8 %self, i64 40, i1 false)
  ret void
}

; <misanthropic::client::Error as core::fmt::Debug>::fmt
; Function Attrs: inlinehint uwtable
define hidden zeroext i1 @"_ZN64_$LT$misanthropic..client..Error$u20$as$u20$core..fmt..Debug$GT$3fmt17h64ce421a790cda37E"(ptr align 8 %self, ptr align 8 %f) unnamed_addr #0 {
start:
  %__self_03 = alloca [8 x i8], align 8
  %__self_1 = alloca [8 x i8], align 8
  %__self_02 = alloca [8 x i8], align 8
  %__self_01 = alloca [8 x i8], align 8
  %__self_0 = alloca [8 x i8], align 8
  %_0 = alloca [1 x i8], align 1
  %0 = load i16, ptr %self, align 8
  %1 = sub i16 %0, 11
  %2 = zext i16 %1 to i64
  %3 = icmp ule i16 %1, 4
  %_3 = select i1 %3, i64 %2, i64 2
  switch i64 %_3, label %bb1 [
    i64 0, label %bb6
    i64 1, label %bb5
    i64 2, label %bb4
    i64 3, label %bb3
    i64 4, label %bb2
  ]

bb1:                                              ; preds = %start
  unreachable

bb6:                                              ; preds = %start
  %4 = getelementptr inbounds i8, ptr %self, i64 8
  store ptr %4, ptr %__self_0, align 8
; call core::fmt::Formatter::debug_tuple_field1_finish
  %5 = call zeroext i1 @_ZN4core3fmt9Formatter25debug_tuple_field1_finish17h62c9088540f0bcd6E(ptr align 8 %f, ptr align 1 @alloc_7010aabf0bbde7181fd2cd0d0ef3d0b6, i64 4, ptr align 1 %__self_0, ptr align 8 @vtable.3)
  %6 = zext i1 %5 to i8
  store i8 %6, ptr %_0, align 1
  br label %bb7

bb5:                                              ; preds = %start
  %7 = getelementptr inbounds i8, ptr %self, i64 8
  store ptr %7, ptr %__self_01, align 8
; call core::fmt::Formatter::debug_tuple_field1_finish
  %8 = call zeroext i1 @_ZN4core3fmt9Formatter25debug_tuple_field1_finish17h62c9088540f0bcd6E(ptr align 8 %f, ptr align 1 @alloc_4cf7911ffc1fa65c3bf9af4755f6af39, i64 5, ptr align 1 %__self_01, ptr align 8 @vtable.4)
  %9 = zext i1 %8 to i8
  store i8 %9, ptr %_0, align 1
  br label %bb7

bb4:                                              ; preds = %start
  store ptr %self, ptr %__self_02, align 8
; call core::fmt::Formatter::debug_tuple_field1_finish
  %10 = call zeroext i1 @_ZN4core3fmt9Formatter25debug_tuple_field1_finish17h62c9088540f0bcd6E(ptr align 8 %f, ptr align 1 @alloc_4f9dfe8db7ef1972eeb96fcb1ae92451, i64 9, ptr align 1 %__self_02, ptr align 8 @vtable.5)
  %11 = zext i1 %10 to i8
  store i8 %11, ptr %_0, align 1
  br label %bb7

bb3:                                              ; preds = %start
  %__self_04 = getelementptr inbounds i8, ptr %self, i64 32
  %12 = getelementptr inbounds i8, ptr %self, i64 8
  store ptr %12, ptr %__self_1, align 8
; call core::fmt::Formatter::debug_struct_field2_finish
  %13 = call zeroext i1 @_ZN4core3fmt9Formatter26debug_struct_field2_finish17h3e899b71a0c5fe87E(ptr align 8 %f, ptr align 1 @alloc_c2314664d27a3f931673074da5b6f66e, i64 15, ptr align 1 @alloc_8c9844c3a6a90a848028a03437183c9a, i64 6, ptr align 1 %__self_04, ptr align 8 @vtable.6, ptr align 1 @alloc_9bb804543209f5e9a668d8c1849e00ff, i64 4, ptr align 1 %__self_1, ptr align 8 @vtable.7)
  %14 = zext i1 %13 to i8
  store i8 %14, ptr %_0, align 1
  br label %bb7

bb2:                                              ; preds = %start
  %15 = getelementptr inbounds i8, ptr %self, i64 8
  store ptr %15, ptr %__self_03, align 8
; call core::fmt::Formatter::debug_struct_field1_finish
  %16 = call zeroext i1 @_ZN4core3fmt9Formatter26debug_struct_field1_finish17h31f5b3c155657224E(ptr align 8 %f, ptr align 1 @alloc_4186248dfa37f30b0aa4551d6079aced, i64 18, ptr align 1 @alloc_96af468510ea8f5f9cb1c5ccd138c101, i64 7, ptr align 1 %__self_03, ptr align 8 @vtable.8)
  %17 = zext i1 %16 to i8
  store i8 %17, ptr %_0, align 1
  br label %bb7

bb7:                                              ; preds = %bb2, %bb3, %bb4, %bb5, %bb6
  %18 = load i8, ptr %_0, align 1
  %19 = trunc nuw i8 %18 to i1
  ret i1 %19
}

; <alloc::sync::Arc<T,A> as core::ops::drop::Drop>::drop
; Function Attrs: inlinehint uwtable
define void @"_ZN71_$LT$alloc..sync..Arc$LT$T$C$A$GT$$u20$as$u20$core..ops..drop..Drop$GT$4drop17h871fbda61cb6d929E"(ptr align 8 %self) unnamed_addr #0 {
start:
  %0 = alloca [8 x i8], align 8
  %_10 = load ptr, ptr %self, align 8
  %1 = atomicrmw sub ptr %_10, i64 1 release, align 8
  store i64 %1, ptr %0, align 8
  %_2 = load i64, ptr %0, align 8
  %2 = icmp eq i64 %_2, 1
  br i1 %2, label %bb2, label %bb1

bb2:                                              ; preds = %start
  fence acquire
; call alloc::sync::Arc<T,A>::drop_slow
  call void @"_ZN5alloc4sync16Arc$LT$T$C$A$GT$9drop_slow17h5fab925c6c5d111eE"(ptr align 8 %self)
  br label %bb3

bb1:                                              ; preds = %start
  br label %bb3

bb3:                                              ; preds = %bb1, %bb2
  ret void
}

; <alloc::sync::Weak<T,A> as core::ops::drop::Drop>::drop
; Function Attrs: uwtable
define void @"_ZN72_$LT$alloc..sync..Weak$LT$T$C$A$GT$$u20$as$u20$core..ops..drop..Drop$GT$4drop17h4332bdb7e5fd6c2bE"(ptr align 8 %self) unnamed_addr #1 {
start:
  %0 = alloca [8 x i8], align 8
  %1 = alloca [8 x i8], align 8
  %2 = alloca [8 x i8], align 8
  %_2 = alloca [16 x i8], align 8
  %self1 = load ptr, ptr %self, align 8
  %_21 = ptrtoint ptr %self1 to i64
  %_16 = icmp eq i64 %_21, -1
  br i1 %_16, label %bb6, label %bb7

bb7:                                              ; preds = %start
  %_20 = getelementptr inbounds i8, ptr %self1, i64 8
  store ptr %_20, ptr %_2, align 8
  %3 = getelementptr inbounds i8, ptr %_2, i64 8
  store ptr %self1, ptr %3, align 8
  %inner = load ptr, ptr %_2, align 8
  %4 = getelementptr inbounds i8, ptr %_2, i64 8
  %inner2 = load ptr, ptr %4, align 8
  %5 = atomicrmw sub ptr %inner, i64 1 release, align 8
  store i64 %5, ptr %2, align 8
  %_3 = load i64, ptr %2, align 8
  %6 = icmp eq i64 %_3, 1
  br i1 %6, label %bb1, label %bb3

bb6:                                              ; preds = %start
  br label %bb5

bb1:                                              ; preds = %bb7
  fence acquire
  %_8 = getelementptr inbounds i8, ptr %self, i64 8
  %self3 = load ptr, ptr %self, align 8
  %self4 = load ptr, ptr %self, align 8
  store i64 40, ptr %1, align 8
  %size = load i64, ptr %1, align 8
  store i64 8, ptr %0, align 8
  %align = load i64, ptr %0, align 8
  br label %bb12

bb3:                                              ; preds = %bb7
  br label %bb4

bb12:                                             ; preds = %bb1
; call core::alloc::layout::Layout::from_size_align_unchecked::precondition_check
  call void @_ZN4core5alloc6layout6Layout25from_size_align_unchecked18precondition_check17h57cfff5f5b8f7ed3E(i64 %size, i64 %align) #18
  br label %bb13

bb13:                                             ; preds = %bb12
; call <&A as core::alloc::Allocator>::deallocate
  call void @"_ZN48_$LT$$RF$A$u20$as$u20$core..alloc..Allocator$GT$10deallocate17h107742a4aaca0c59E"(ptr align 8 %_8, ptr %self3, i64 %align, i64 %size)
  br label %bb4

bb4:                                              ; preds = %bb3, %bb13
  br label %bb5

bb5:                                              ; preds = %bb6, %bb4
  ret void
}

; <misanthropic::client::AnthropicError as core::fmt::Debug>::fmt
; Function Attrs: inlinehint uwtable
define hidden zeroext i1 @"_ZN73_$LT$misanthropic..client..AnthropicError$u20$as$u20$core..fmt..Debug$GT$3fmt17hf27a5a97a58bbc9cE"(ptr align 8 %self, ptr align 8 %f) unnamed_addr #0 {
start:
  %__self_19 = alloca [8 x i8], align 8
  %__self_08 = alloca [8 x i8], align 8
  %__self_17 = alloca [8 x i8], align 8
  %__self_06 = alloca [8 x i8], align 8
  %__self_1 = alloca [8 x i8], align 8
  %__self_05 = alloca [8 x i8], align 8
  %__self_04 = alloca [8 x i8], align 8
  %__self_03 = alloca [8 x i8], align 8
  %__self_02 = alloca [8 x i8], align 8
  %__self_01 = alloca [8 x i8], align 8
  %__self_0 = alloca [8 x i8], align 8
  %_0 = alloca [1 x i8], align 1
  %0 = load i16, ptr %self, align 8
  %_3 = zext i16 %0 to i64
  switch i64 %_3, label %bb1 [
    i64 0, label %bb12
    i64 1, label %bb11
    i64 2, label %bb10
    i64 3, label %bb9
    i64 4, label %bb8
    i64 5, label %bb7
    i64 6, label %bb6
    i64 7, label %bb5
    i64 8, label %bb4
    i64 9, label %bb3
    i64 10, label %bb2
  ]

bb1:                                              ; preds = %start
  unreachable

bb12:                                             ; preds = %start
  %1 = getelementptr inbounds i8, ptr %self, i64 8
  store ptr %1, ptr %__self_0, align 8
; call core::fmt::Formatter::debug_struct_field1_finish
  %2 = call zeroext i1 @_ZN4core3fmt9Formatter26debug_struct_field1_finish17h31f5b3c155657224E(ptr align 8 %f, ptr align 1 @alloc_0041846db82c81f9b8ef910951b86b6f, i64 14, ptr align 1 @alloc_96af468510ea8f5f9cb1c5ccd138c101, i64 7, ptr align 1 %__self_0, ptr align 8 @vtable.7)
  %3 = zext i1 %2 to i8
  store i8 %3, ptr %_0, align 1
  br label %bb13

bb11:                                             ; preds = %start
  %4 = getelementptr inbounds i8, ptr %self, i64 8
  store ptr %4, ptr %__self_01, align 8
; call core::fmt::Formatter::debug_struct_field1_finish
  %5 = call zeroext i1 @_ZN4core3fmt9Formatter26debug_struct_field1_finish17h31f5b3c155657224E(ptr align 8 %f, ptr align 1 @alloc_45500aec4bb0c69d950f9beca84dd93c, i64 14, ptr align 1 @alloc_96af468510ea8f5f9cb1c5ccd138c101, i64 7, ptr align 1 %__self_01, ptr align 8 @vtable.7)
  %6 = zext i1 %5 to i8
  store i8 %6, ptr %_0, align 1
  br label %bb13

bb10:                                             ; preds = %start
  %7 = getelementptr inbounds i8, ptr %self, i64 8
  store ptr %7, ptr %__self_02, align 8
; call core::fmt::Formatter::debug_struct_field1_finish
  %8 = call zeroext i1 @_ZN4core3fmt9Formatter26debug_struct_field1_finish17h31f5b3c155657224E(ptr align 8 %f, ptr align 1 @alloc_ab7ae8aa2c83156c614e7c90bf3a5bc2, i64 7, ptr align 1 @alloc_96af468510ea8f5f9cb1c5ccd138c101, i64 7, ptr align 1 %__self_02, ptr align 8 @vtable.7)
  %9 = zext i1 %8 to i8
  store i8 %9, ptr %_0, align 1
  br label %bb13

bb9:                                              ; preds = %start
  %10 = getelementptr inbounds i8, ptr %self, i64 8
  store ptr %10, ptr %__self_03, align 8
; call core::fmt::Formatter::debug_struct_field1_finish
  %11 = call zeroext i1 @_ZN4core3fmt9Formatter26debug_struct_field1_finish17h31f5b3c155657224E(ptr align 8 %f, ptr align 1 @alloc_8e658b02a36b8853f273c1d5759f7875, i64 10, ptr align 1 @alloc_96af468510ea8f5f9cb1c5ccd138c101, i64 7, ptr align 1 %__self_03, ptr align 8 @vtable.7)
  %12 = zext i1 %11 to i8
  store i8 %12, ptr %_0, align 1
  br label %bb13

bb8:                                              ; preds = %start
  %13 = getelementptr inbounds i8, ptr %self, i64 8
  store ptr %13, ptr %__self_04, align 8
; call core::fmt::Formatter::debug_struct_field1_finish
  %14 = call zeroext i1 @_ZN4core3fmt9Formatter26debug_struct_field1_finish17h31f5b3c155657224E(ptr align 8 %f, ptr align 1 @alloc_2201031af4f3db2ffa8285dddc089c29, i64 8, ptr align 1 @alloc_96af468510ea8f5f9cb1c5ccd138c101, i64 7, ptr align 1 %__self_04, ptr align 8 @vtable.7)
  %15 = zext i1 %14 to i8
  store i8 %15, ptr %_0, align 1
  br label %bb13

bb7:                                              ; preds = %start
  %16 = getelementptr inbounds i8, ptr %self, i64 8
  store ptr %16, ptr %__self_05, align 8
; call core::fmt::Formatter::debug_struct_field1_finish
  %17 = call zeroext i1 @_ZN4core3fmt9Formatter26debug_struct_field1_finish17h31f5b3c155657224E(ptr align 8 %f, ptr align 1 @alloc_fe96f81fcb62c98a919cec1e88b6a877, i64 15, ptr align 1 @alloc_96af468510ea8f5f9cb1c5ccd138c101, i64 7, ptr align 1 %__self_05, ptr align 8 @vtable.7)
  %18 = zext i1 %17 to i8
  store i8 %18, ptr %_0, align 1
  br label %bb13

bb6:                                              ; preds = %start
  %__self_010 = getelementptr inbounds i8, ptr %self, i64 8
  %19 = getelementptr inbounds i8, ptr %self, i64 32
  store ptr %19, ptr %__self_1, align 8
; call core::fmt::Formatter::debug_struct_field2_finish
  %20 = call zeroext i1 @_ZN4core3fmt9Formatter26debug_struct_field2_finish17h3e899b71a0c5fe87E(ptr align 8 %f, ptr align 1 @alloc_5313b5e80a18a1a56efbc1c873514882, i64 9, ptr align 1 @alloc_96af468510ea8f5f9cb1c5ccd138c101, i64 7, ptr align 1 %__self_010, ptr align 8 @vtable.9, ptr align 1 @alloc_da9fc84f456a7be3794db92d01144896, i64 11, ptr align 1 %__self_1, ptr align 8 @vtable.a)
  %21 = zext i1 %20 to i8
  store i8 %21, ptr %_0, align 1
  br label %bb13

bb5:                                              ; preds = %start
  %22 = getelementptr inbounds i8, ptr %self, i64 8
  store ptr %22, ptr %__self_06, align 8
; call core::fmt::Formatter::debug_struct_field1_finish
  %23 = call zeroext i1 @_ZN4core3fmt9Formatter26debug_struct_field1_finish17h31f5b3c155657224E(ptr align 8 %f, ptr align 1 @alloc_101ac9f1b2ce360b71b12e4e7448d994, i64 3, ptr align 1 @alloc_96af468510ea8f5f9cb1c5ccd138c101, i64 7, ptr align 1 %__self_06, ptr align 8 @vtable.7)
  %24 = zext i1 %23 to i8
  store i8 %24, ptr %_0, align 1
  br label %bb13

bb4:                                              ; preds = %start
  %__self_011 = getelementptr inbounds i8, ptr %self, i64 8
  %25 = getelementptr inbounds i8, ptr %self, i64 32
  store ptr %25, ptr %__self_17, align 8
; call core::fmt::Formatter::debug_struct_field2_finish
  %26 = call zeroext i1 @_ZN4core3fmt9Formatter26debug_struct_field2_finish17h3e899b71a0c5fe87E(ptr align 8 %f, ptr align 1 @alloc_9d2eeace429a5efc7f5121129f353534, i64 10, ptr align 1 @alloc_96af468510ea8f5f9cb1c5ccd138c101, i64 7, ptr align 1 %__self_011, ptr align 8 @vtable.9, ptr align 1 @alloc_da9fc84f456a7be3794db92d01144896, i64 11, ptr align 1 %__self_17, ptr align 8 @vtable.a)
  %27 = zext i1 %26 to i8
  store i8 %27, ptr %_0, align 1
  br label %bb13

bb3:                                              ; preds = %start
  %28 = getelementptr inbounds i8, ptr %self, i64 8
  store ptr %28, ptr %__self_08, align 8
; call core::fmt::Formatter::debug_struct_field1_finish
  %29 = call zeroext i1 @_ZN4core3fmt9Formatter26debug_struct_field1_finish17h31f5b3c155657224E(ptr align 8 %f, ptr align 1 @alloc_42706ad80c424b77359f062cdf071eb7, i64 7, ptr align 1 @alloc_96af468510ea8f5f9cb1c5ccd138c101, i64 7, ptr align 1 %__self_08, ptr align 8 @vtable.7)
  %30 = zext i1 %29 to i8
  store i8 %30, ptr %_0, align 1
  br label %bb13

bb2:                                              ; preds = %start
  %__self_012 = getelementptr inbounds i8, ptr %self, i64 2
  %31 = getelementptr inbounds i8, ptr %self, i64 8
  store ptr %31, ptr %__self_19, align 8
; call core::fmt::Formatter::debug_struct_field2_finish
  %32 = call zeroext i1 @_ZN4core3fmt9Formatter26debug_struct_field2_finish17h3e899b71a0c5fe87E(ptr align 8 %f, ptr align 1 @alloc_8cc9588efcf35543a364a34123fcfef9, i64 7, ptr align 1 @alloc_905976595ed1b08e57e2b44a2acadea4, i64 4, ptr align 1 %__self_012, ptr align 8 @vtable.b, ptr align 1 @alloc_96af468510ea8f5f9cb1c5ccd138c101, i64 7, ptr align 1 %__self_19, ptr align 8 @vtable.7)
  %33 = zext i1 %32 to i8
  store i8 %33, ptr %_0, align 1
  br label %bb13

bb13:                                             ; preds = %bb2, %bb3, %bb4, %bb5, %bb6, %bb7, %bb8, %bb9, %bb10, %bb11, %bb12
  %34 = load i8, ptr %_0, align 1
  %35 = trunc nuw i8 %34 to i1
  ret i1 %35
}

; <misanthropic::prompt::TurnOrderError as core::fmt::Debug>::fmt
; Function Attrs: inlinehint uwtable
define hidden zeroext i1 @"_ZN73_$LT$misanthropic..prompt..TurnOrderError$u20$as$u20$core..fmt..Debug$GT$3fmt17h351c0bf5472a2e32E"(ptr align 8 %self, ptr align 8 %f) unnamed_addr #0 {
start:
  %__self_12 = alloca [8 x i8], align 8
  %__self_01 = alloca [8 x i8], align 8
  %__self_1 = alloca [8 x i8], align 8
  %__self_0 = alloca [8 x i8], align 8
  %_0 = alloca [1 x i8], align 1
  %0 = load i64, ptr %self, align 8
  %1 = sub i64 %0, -9223372036854775808
  %2 = icmp ule i64 %1, 3
  %_3 = select i1 %2, i64 %1, i64 1
  switch i64 %_3, label %bb1 [
    i64 0, label %bb5
    i64 1, label %bb4
    i64 2, label %bb3
    i64 3, label %bb2
  ]

bb1:                                              ; preds = %start
  unreachable

bb5:                                              ; preds = %start
  %3 = getelementptr inbounds i8, ptr %self, i64 8
  store ptr %3, ptr %__self_0, align 8
; call core::fmt::Formatter::debug_struct_field1_finish
  %4 = call zeroext i1 @_ZN4core3fmt9Formatter26debug_struct_field1_finish17h31f5b3c155657224E(ptr align 8 %f, ptr align 1 @alloc_be476ef6c975aeef42849d7343768d87, i64 8, ptr align 1 @alloc_96af468510ea8f5f9cb1c5ccd138c101, i64 7, ptr align 1 %__self_0, ptr align 8 @vtable.c)
  %5 = zext i1 %4 to i8
  store i8 %5, ptr %_0, align 1
  br label %bb6

bb4:                                              ; preds = %start
  %6 = getelementptr inbounds i8, ptr %self, i64 32
  store ptr %6, ptr %__self_1, align 8
; call core::fmt::Formatter::debug_struct_field2_finish
  %7 = call zeroext i1 @_ZN4core3fmt9Formatter26debug_struct_field2_finish17h3e899b71a0c5fe87E(ptr align 8 %f, ptr align 1 @alloc_34e47e1681a65ce9ec811b023e78c3d8, i64 13, ptr align 1 @alloc_4986dd618090c125bc3e853ec5468cc0, i64 5, ptr align 1 %self, ptr align 8 @vtable.d, ptr align 1 @alloc_114ee15010692784d7aa12af2dd225dd, i64 6, ptr align 1 %__self_1, ptr align 8 @vtable.c)
  %8 = zext i1 %7 to i8
  store i8 %8, ptr %_0, align 1
  br label %bb6

bb3:                                              ; preds = %start
  %9 = getelementptr inbounds i8, ptr %self, i64 8
  store ptr %9, ptr %__self_01, align 8
; call core::fmt::Formatter::debug_struct_field1_finish
  %10 = call zeroext i1 @_ZN4core3fmt9Formatter26debug_struct_field1_finish17h31f5b3c155657224E(ptr align 8 %f, ptr align 1 @alloc_1d7c4d8451edc87804c9969173e3ec5f, i64 20, ptr align 1 @alloc_96af468510ea8f5f9cb1c5ccd138c101, i64 7, ptr align 1 %__self_01, ptr align 8 @vtable.c)
  %11 = zext i1 %10 to i8
  store i8 %11, ptr %_0, align 1
  br label %bb6

bb2:                                              ; preds = %start
  %__self_03 = getelementptr inbounds i8, ptr %self, i64 8
  %12 = getelementptr inbounds i8, ptr %self, i64 40
  store ptr %12, ptr %__self_12, align 8
; call core::fmt::Formatter::debug_struct_field2_finish
  %13 = call zeroext i1 @_ZN4core3fmt9Formatter26debug_struct_field2_finish17h3e899b71a0c5fe87E(ptr align 8 %f, ptr align 1 @alloc_84c53b99ad03075cd02fc91e54d3a4e1, i64 17, ptr align 1 @alloc_96af468510ea8f5f9cb1c5ccd138c101, i64 7, ptr align 1 %__self_03, ptr align 8 @vtable.d, ptr align 1 @alloc_067fc2ed276f3eb6967fc46f7feae7a6, i64 10, ptr align 1 %__self_12, ptr align 8 @vtable.e)
  %14 = zext i1 %13 to i8
  store i8 %14, ptr %_0, align 1
  br label %bb6

bb6:                                              ; preds = %bb2, %bb3, %bb4, %bb5
  %15 = load i8, ptr %_0, align 1
  %16 = trunc nuw i8 %15 to i1
  ret i1 %16
}

; <usize as core::slice::index::SliceIndex<[T]>>::get_unchecked::precondition_check
; Function Attrs: inlinehint nounwind uwtable
define hidden void @"_ZN75_$LT$usize$u20$as$u20$core..slice..index..SliceIndex$LT$$u5b$T$u5d$$GT$$GT$13get_unchecked18precondition_check17h710e408a1265e886E"(i64 %this, i64 %len) unnamed_addr #2 {
start:
  %_3 = icmp ult i64 %this, %len
  br i1 %_3, label %bb1, label %bb2

bb2:                                              ; preds = %start
; call core::panicking::panic_nounwind
  call void @_ZN4core9panicking14panic_nounwind17hb115782c8cb05dd0E(ptr align 1 @alloc_97d92cbf2a68a6ac45a1b13da79836e4, i64 214) #15
  unreachable

bb1:                                              ; preds = %start
  ret void
}

; <core::result::Result<T,E> as core::ops::try_trait::Try>::branch
; Function Attrs: inlinehint uwtable
define void @"_ZN79_$LT$core..result..Result$LT$T$C$E$GT$$u20$as$u20$core..ops..try_trait..Try$GT$6branch17h434501de076f7e7bE"(ptr sret([112 x i8]) align 8 %_0, ptr align 8 %self) unnamed_addr #0 {
start:
  %_5 = alloca [8 x i8], align 8
  %v = alloca [108 x i8], align 1
  %0 = load i8, ptr %self, align 8
  %1 = trunc nuw i8 %0 to i1
  %_2 = zext i1 %1 to i64
  %2 = trunc nuw i64 %_2 to i1
  br i1 %2, label %bb2, label %bb3

bb2:                                              ; preds = %start
  %3 = getelementptr inbounds i8, ptr %self, i64 8
  %e = load i64, ptr %3, align 8
  store i64 %e, ptr %_5, align 8
  %4 = load i64, ptr %_5, align 8
  %5 = getelementptr inbounds i8, ptr %_0, i64 8
  store i64 %4, ptr %5, align 8
  store i8 1, ptr %_0, align 8
  br label %bb4

bb3:                                              ; preds = %start
  %6 = getelementptr inbounds i8, ptr %self, i64 1
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %v, ptr align 1 %6, i64 108, i1 false)
  %7 = getelementptr inbounds i8, ptr %_0, i64 1
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %7, ptr align 1 %v, i64 108, i1 false)
  store i8 0, ptr %_0, align 8
  br label %bb4

bb4:                                              ; preds = %bb2, %bb3
  ret void

bb1:                                              ; No predecessors!
  unreachable
}

; <core::array::iter::IntoIter<T,_> as core::ops::drop::Drop>::drop
; Function Attrs: inlinehint uwtable
define void @"_ZN82_$LT$core..array..iter..IntoIter$LT$T$C$_$GT$$u20$as$u20$core..ops..drop..Drop$GT$4drop17h351356d19c94e25aE"(ptr align 8 %self) unnamed_addr #0 {
start:
  ret void
}

; <misanthropic::key::unencrypted::InvalidKeyLength as core::fmt::Debug>::fmt
; Function Attrs: inlinehint uwtable
define hidden zeroext i1 @"_ZN85_$LT$misanthropic..key..unencrypted..InvalidKeyLength$u20$as$u20$core..fmt..Debug$GT$3fmt17h1ca2bc38c221c87cE"(ptr align 8 %self, ptr align 8 %f) unnamed_addr #0 {
start:
  %_7 = alloca [8 x i8], align 8
  store ptr %self, ptr %_7, align 8
; call core::fmt::Formatter::debug_struct_field1_finish
  %_0 = call zeroext i1 @_ZN4core3fmt9Formatter26debug_struct_field1_finish17h31f5b3c155657224E(ptr align 8 %f, ptr align 1 @alloc_920d1ade628fe08e7464cf813a42b3be, i64 16, ptr align 1 @alloc_b31c6c8dca3d1da07e1eee656fa2f5cc, i64 6, ptr align 1 %_7, ptr align 8 @vtable.f)
  ret i1 %_0
}

; <misanthropic::prompt::message::Content as core::convert::From<T>>::from
; Function Attrs: uwtable
define void @"_ZN87_$LT$misanthropic..prompt..message..Content$u20$as$u20$core..convert..From$LT$T$GT$$GT$4from17h282ef9696aa6f308E"(ptr sret([24 x i8]) align 8 %_0, ptr align 1 %block.0, i64 %block.1) unnamed_addr #1 personality ptr @__CxxFrameHandler3 {
start:
  %_11 = alloca [1 x i8], align 1
  %_9 = alloca [208 x i8], align 8
  %_8 = alloca [8 x i8], align 8
  %_2 = alloca [24 x i8], align 8
  store i8 0, ptr %_11, align 1
  store i8 1, ptr %_11, align 1
; invoke alloc::alloc::exchange_malloc
  %_7 = invoke ptr @_ZN5alloc5alloc15exchange_malloc17h2cfa1ed50d4343f0E(i64 208, i64 8)
          to label %bb1 unwind label %funclet_bb7

bb7:                                              ; preds = %funclet_bb7
  %0 = load i8, ptr %_11, align 1
  %1 = trunc nuw i8 %0 to i1
  br i1 %1, label %bb6, label %bb4

funclet_bb7:                                      ; preds = %bb5, %bb9, %start
  %cleanuppad = cleanuppad within none []
  br label %bb7

bb1:                                              ; preds = %start
  store ptr %_7, ptr %_8, align 8
  store i8 0, ptr %_11, align 1
; invoke <T as core::convert::Into<U>>::into
  invoke void @"_ZN50_$LT$T$u20$as$u20$core..convert..Into$LT$U$GT$$GT$4into17h8ea7934fb5035da2E"(ptr sret([208 x i8]) align 8 %_9, ptr align 1 %block.0, i64 %block.1, ptr align 8 @alloc_62f0ea6b413625199824bf4fe7be34c8)
          to label %bb2 unwind label %funclet_bb5

bb5:                                              ; preds = %funclet_bb5
; call <alloc::boxed::Box<T,A> as core::ops::drop::Drop>::drop
  call void @"_ZN72_$LT$alloc..boxed..Box$LT$T$C$A$GT$$u20$as$u20$core..ops..drop..Drop$GT$4drop17h6693a0875a8ffe17E"(ptr align 8 %_8) #17 [ "funclet"(token %cleanuppad1) ]
  cleanupret from %cleanuppad1 unwind label %funclet_bb7

funclet_bb5:                                      ; preds = %bb1
  %cleanuppad1 = cleanuppad within none []
  br label %bb5

bb2:                                              ; preds = %bb1
  %_14 = load ptr, ptr %_8, align 8
  %_16 = ptrtoint ptr %_14 to i64
  %_19 = and i64 %_16, 7
  %_20 = icmp eq i64 %_19, 0
  br i1 %_20, label %bb8, label %panic

bb8:                                              ; preds = %bb2
  %_22 = ptrtoint ptr %_14 to i64
  %_25 = icmp eq i64 %_22, 0
  %_26 = and i1 %_25, true
  %_27 = xor i1 %_26, true
  br i1 %_27, label %bb9, label %panic2

panic:                                            ; preds = %bb2
; call core::panicking::panic_misaligned_pointer_dereference
  call void @_ZN4core9panicking36panic_misaligned_pointer_dereference17hdbae00d467f272e7E(i64 8, i64 %_16, ptr align 8 @alloc_cbfdeea429b96084b620ff74647c466b) #15
  unreachable

bb9:                                              ; preds = %bb8
  %2 = getelementptr inbounds nuw %"misanthropic::prompt::message::Block", ptr %_14, i64 0
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %2, ptr align 8 %_9, i64 208, i1 false)
  %_4 = load ptr, ptr %_8, align 8
; invoke alloc::slice::<impl [T]>::into_vec
  invoke void @"_ZN5alloc5slice29_$LT$impl$u20$$u5b$T$u5d$$GT$8into_vec17h35e534e91cab947fE"(ptr sret([24 x i8]) align 8 %_2, ptr align 8 %_4, i64 1)
          to label %bb3 unwind label %funclet_bb7

panic2:                                           ; preds = %bb8
; call core::panicking::panic_null_pointer_dereference
  call void @_ZN4core9panicking30panic_null_pointer_dereference17h4567733e82a6ba35E(ptr align 8 @alloc_cbfdeea429b96084b620ff74647c466b) #15
  unreachable

bb3:                                              ; preds = %bb9
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_0, ptr align 8 %_2, i64 24, i1 false)
  ret void

bb4:                                              ; preds = %bb6, %bb7
  cleanupret from %cleanuppad unwind to caller

bb6:                                              ; preds = %bb7
  br label %bb4
}

; <core::ops::index_range::IndexRange as core::iter::traits::iterator::Iterator>::try_fold
; Function Attrs: inlinehint uwtable
define void @"_ZN93_$LT$core..ops..index_range..IndexRange$u20$as$u20$core..iter..traits..iterator..Iterator$GT$8try_fold17h533f71010b1bd8daE"(ptr align 8 %self, ptr align 8 %f) unnamed_addr #0 personality ptr @__CxxFrameHandler3 {
start:
  %_17 = alloca [1 x i8], align 1
  %_19 = load i64, ptr %self, align 8
  %0 = getelementptr inbounds i8, ptr %self, i64 8
  %_20 = load i64, ptr %0, align 8
  %cond = icmp ule i64 %_19, %_20
  br label %bb16

bb16:                                             ; preds = %start
; call core::hint::assert_unchecked::precondition_check
  call void @_ZN4core4hint16assert_unchecked18precondition_check17he63daafc4d26dafdE(i1 zeroext %cond) #18
  br label %bb17

bb17:                                             ; preds = %bb16
  br label %bb1

bb1:                                              ; preds = %bb6, %bb17
  %_5 = load i64, ptr %self, align 8
  %1 = getelementptr inbounds i8, ptr %self, i64 8
  %_6 = load i64, ptr %1, align 8
  %_4 = icmp ne i64 %_5, %_6
  br i1 %_4, label %bb2, label %bb9

bb9:                                              ; preds = %bb1
  store i8 0, ptr %_17, align 1
; invoke <core::ops::try_trait::NeverShortCircuit<T> as core::ops::try_trait::Try>::from_output
  invoke void @"_ZN94_$LT$core..ops..try_trait..NeverShortCircuit$LT$T$GT$$u20$as$u20$core..ops..try_trait..Try$GT$11from_output17h1e911e73c83835f8E"()
          to label %bb10 unwind label %funclet_bb12

bb2:                                              ; preds = %bb1
  %i = load i64, ptr %self, align 8
  br label %bb18

bb12:                                             ; preds = %funclet_bb12
; call core::ptr::drop_in_place<core::array::iter::iter_inner::PolymorphicIter<[core::mem::maybe_uninit::MaybeUninit<(misanthropic::prompt::message::Role,&str)>]>::try_fold<(),core::ops::try_trait::NeverShortCircuit<()>::wrap_mut_2<(),(misanthropic::prompt::message::Role,&str),core::iter::adapters::map::map_fold<(misanthropic::prompt::message::Role,&str),misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>,(),<(misanthropic::prompt::message::Role,&str) as core::convert::Into<misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>>>::into,core::iter::traits::iterator::Iterator::for_each::call<misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>,alloc::vec::Vec<misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>>::extend_trusted<core::iter::adapters::map::Map<core::array::iter::IntoIter<(misanthropic::prompt::message::Role,&str),1_usize>,<(misanthropic::prompt::message::Role,&str) as core::convert::Into<misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>>>::into>>::{{closure}}>::{{closure}}>::{{closure}}>::{{closure}},core::ops::try_trait::NeverShortCircuit<()>>::{{closure}}>
  call void @"_ZN4core3ptr1560drop_in_place$LT$core..array..iter..iter_inner..PolymorphicIter$LT$$u5b$core..mem..maybe_uninit..MaybeUninit$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$GT$$u5d$$GT$..try_fold$LT$$LP$$RP$$C$core..ops..try_trait..NeverShortCircuit$LT$$LP$$RP$$GT$..wrap_mut_2$LT$$LP$$RP$$C$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$C$core..iter..adapters..map..map_fold$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$C$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$C$$LP$$RP$$C$$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$u20$as$u20$core..convert..Into$LT$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$GT$$GT$..into$C$core..iter..traits..iterator..Iterator..for_each..call$LT$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$C$alloc..vec..Vec$LT$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$GT$..extend_trusted$LT$core..iter..adapters..map..Map$LT$core..array..iter..IntoIter$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$C$1_usize$GT$$C$$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$u20$as$u20$core..convert..Into$LT$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$GT$$GT$..into$GT$$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$..$u7b$$u7b$closure$u7d$$u7d$$C$core..ops..try_trait..NeverShortCircuit$LT$$LP$$RP$$GT$$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$17h127e08b51e4d053cE"(ptr align 8 %f) #17 [ "funclet"(token %cleanuppad) ]
  cleanupret from %cleanuppad unwind label %funclet_bb15

funclet_bb12:                                     ; preds = %bb7, %bb3, %bb19, %bb9
  %cleanuppad = cleanuppad within none []
  br label %bb12

bb10:                                             ; preds = %bb9
; invoke core::ptr::drop_in_place<core::array::iter::iter_inner::PolymorphicIter<[core::mem::maybe_uninit::MaybeUninit<(misanthropic::prompt::message::Role,&str)>]>::try_fold<(),core::ops::try_trait::NeverShortCircuit<()>::wrap_mut_2<(),(misanthropic::prompt::message::Role,&str),core::iter::adapters::map::map_fold<(misanthropic::prompt::message::Role,&str),misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>,(),<(misanthropic::prompt::message::Role,&str) as core::convert::Into<misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>>>::into,core::iter::traits::iterator::Iterator::for_each::call<misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>,alloc::vec::Vec<misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>>::extend_trusted<core::iter::adapters::map::Map<core::array::iter::IntoIter<(misanthropic::prompt::message::Role,&str),1_usize>,<(misanthropic::prompt::message::Role,&str) as core::convert::Into<misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>>>::into>>::{{closure}}>::{{closure}}>::{{closure}}>::{{closure}},core::ops::try_trait::NeverShortCircuit<()>>::{{closure}}>
  invoke void @"_ZN4core3ptr1560drop_in_place$LT$core..array..iter..iter_inner..PolymorphicIter$LT$$u5b$core..mem..maybe_uninit..MaybeUninit$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$GT$$u5d$$GT$..try_fold$LT$$LP$$RP$$C$core..ops..try_trait..NeverShortCircuit$LT$$LP$$RP$$GT$..wrap_mut_2$LT$$LP$$RP$$C$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$C$core..iter..adapters..map..map_fold$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$C$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$C$$LP$$RP$$C$$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$u20$as$u20$core..convert..Into$LT$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$GT$$GT$..into$C$core..iter..traits..iterator..Iterator..for_each..call$LT$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$C$alloc..vec..Vec$LT$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$GT$..extend_trusted$LT$core..iter..adapters..map..Map$LT$core..array..iter..IntoIter$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$C$1_usize$GT$$C$$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$u20$as$u20$core..convert..Into$LT$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$GT$$GT$..into$GT$$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$..$u7b$$u7b$closure$u7d$$u7d$$C$core..ops..try_trait..NeverShortCircuit$LT$$LP$$RP$$GT$$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$17h127e08b51e4d053cE"(ptr align 8 %f)
          to label %bb11 unwind label %funclet_bb15

bb15:                                             ; preds = %funclet_bb15
  %2 = load i8, ptr %_17, align 1
  %3 = trunc nuw i8 %2 to i1
  br i1 %3, label %bb14, label %bb13

funclet_bb15:                                     ; preds = %bb12, %bb8, %bb10
  %cleanuppad1 = cleanuppad within none []
  br label %bb15

bb11:                                             ; preds = %bb8, %bb10
  ret void

bb18:                                             ; preds = %bb2
; call core::num::<impl usize>::unchecked_add::precondition_check
  call void @"_ZN4core3num23_$LT$impl$u20$usize$GT$13unchecked_add18precondition_check17h947eae1af0984b8bE"(i64 %i, i64 1) #18
  br label %bb19

bb19:                                             ; preds = %bb18
  %_23 = add nuw i64 %i, 1
  store i64 %_23, ptr %self, align 8
  store i8 0, ptr %_17, align 1
; invoke core::array::iter::iter_inner::PolymorphicIter<[core::mem::maybe_uninit::MaybeUninit<T>]>::try_fold::{{closure}}
  invoke void @"_ZN4core5array4iter10iter_inner78PolymorphicIter$LT$$u5b$core..mem..maybe_uninit..MaybeUninit$LT$T$GT$$u5d$$GT$8try_fold28_$u7b$$u7b$closure$u7d$$u7d$17h8a7c2865f6b886e8E"(ptr align 8 %f, i64 %i)
          to label %bb3 unwind label %funclet_bb12

bb3:                                              ; preds = %bb19
; invoke <core::ops::try_trait::NeverShortCircuit<T> as core::ops::try_trait::Try>::branch
  invoke void @"_ZN94_$LT$core..ops..try_trait..NeverShortCircuit$LT$T$GT$$u20$as$u20$core..ops..try_trait..Try$GT$6branch17hbbaf3ea4187b2a0cE"()
          to label %bb4 unwind label %funclet_bb12

bb4:                                              ; preds = %bb3
  br label %bb6

bb6:                                              ; preds = %bb4
  br label %bb1

bb7:                                              ; No predecessors!
; invoke <core::ops::try_trait::NeverShortCircuit<T> as core::ops::try_trait::FromResidual<core::ops::try_trait::NeverShortCircuitResidual>>::from_residual
  invoke void @"_ZN158_$LT$core..ops..try_trait..NeverShortCircuit$LT$T$GT$$u20$as$u20$core..ops..try_trait..FromResidual$LT$core..ops..try_trait..NeverShortCircuitResidual$GT$$GT$13from_residual17h065e08a986c6abfcE"()
          to label %bb8 unwind label %funclet_bb12

bb8:                                              ; preds = %bb7
; invoke core::ptr::drop_in_place<core::array::iter::iter_inner::PolymorphicIter<[core::mem::maybe_uninit::MaybeUninit<(misanthropic::prompt::message::Role,&str)>]>::try_fold<(),core::ops::try_trait::NeverShortCircuit<()>::wrap_mut_2<(),(misanthropic::prompt::message::Role,&str),core::iter::adapters::map::map_fold<(misanthropic::prompt::message::Role,&str),misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>,(),<(misanthropic::prompt::message::Role,&str) as core::convert::Into<misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>>>::into,core::iter::traits::iterator::Iterator::for_each::call<misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>,alloc::vec::Vec<misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>>::extend_trusted<core::iter::adapters::map::Map<core::array::iter::IntoIter<(misanthropic::prompt::message::Role,&str),1_usize>,<(misanthropic::prompt::message::Role,&str) as core::convert::Into<misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>>>::into>>::{{closure}}>::{{closure}}>::{{closure}}>::{{closure}},core::ops::try_trait::NeverShortCircuit<()>>::{{closure}}>
  invoke void @"_ZN4core3ptr1560drop_in_place$LT$core..array..iter..iter_inner..PolymorphicIter$LT$$u5b$core..mem..maybe_uninit..MaybeUninit$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$GT$$u5d$$GT$..try_fold$LT$$LP$$RP$$C$core..ops..try_trait..NeverShortCircuit$LT$$LP$$RP$$GT$..wrap_mut_2$LT$$LP$$RP$$C$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$C$core..iter..adapters..map..map_fold$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$C$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$C$$LP$$RP$$C$$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$u20$as$u20$core..convert..Into$LT$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$GT$$GT$..into$C$core..iter..traits..iterator..Iterator..for_each..call$LT$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$C$alloc..vec..Vec$LT$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$GT$..extend_trusted$LT$core..iter..adapters..map..Map$LT$core..array..iter..IntoIter$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$C$1_usize$GT$$C$$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$u20$as$u20$core..convert..Into$LT$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$GT$$GT$..into$GT$$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$..$u7b$$u7b$closure$u7d$$u7d$$C$core..ops..try_trait..NeverShortCircuit$LT$$LP$$RP$$GT$$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$17h127e08b51e4d053cE"(ptr align 8 %f)
          to label %bb11 unwind label %funclet_bb15

bb5:                                              ; No predecessors!
  unreachable

bb13:                                             ; preds = %bb14, %bb15
  cleanupret from %cleanuppad1 unwind to caller

bb14:                                             ; preds = %bb15
  br label %bb13
}

; <alloc::vec::Vec<T> as core::iter::traits::collect::FromIterator<T>>::from_iter
; Function Attrs: inlinehint uwtable
define void @"_ZN95_$LT$alloc..vec..Vec$LT$T$GT$$u20$as$u20$core..iter..traits..collect..FromIterator$LT$T$GT$$GT$9from_iter17hc11902cdaf446d82E"(ptr sret([24 x i8]) align 8 %_0, ptr align 8 %iter, ptr align 8 %0) unnamed_addr #0 {
start:
  %_2 = alloca [40 x i8], align 8
; call <I as core::iter::traits::collect::IntoIterator>::into_iter
  call void @"_ZN63_$LT$I$u20$as$u20$core..iter..traits..collect..IntoIterator$GT$9into_iter17h3fc5d653af7a31f5E"(ptr sret([40 x i8]) align 8 %_2, ptr align 8 %iter)
; call <alloc::vec::Vec<T> as alloc::vec::spec_from_iter::SpecFromIter<T,I>>::from_iter
  call void @"_ZN98_$LT$alloc..vec..Vec$LT$T$GT$$u20$as$u20$alloc..vec..spec_from_iter..SpecFromIter$LT$T$C$I$GT$$GT$9from_iter17h7e287339a7855f7aE"(ptr sret([24 x i8]) align 8 %_0, ptr align 8 %_2, ptr align 8 %0)
  ret void
}

; <alloc::vec::Vec<T,A> as alloc::vec::spec_extend::SpecExtend<T,I>>::spec_extend
; Function Attrs: uwtable
define void @"_ZN97_$LT$alloc..vec..Vec$LT$T$C$A$GT$$u20$as$u20$alloc..vec..spec_extend..SpecExtend$LT$T$C$I$GT$$GT$11spec_extend17h3668163d5ed909c3E"(ptr align 8 %self, ptr align 8 %iterator, ptr align 8 %0) unnamed_addr #1 {
start:
; call alloc::vec::Vec<T,A>::extend_trusted
  call void @"_ZN5alloc3vec16Vec$LT$T$C$A$GT$14extend_trusted17h462e43ac2a13841cE"(ptr align 8 %self, ptr align 8 %iterator, ptr align 8 %0)
  ret void
}

; <alloc::vec::Vec<T> as alloc::vec::spec_from_iter::SpecFromIter<T,I>>::from_iter
; Function Attrs: uwtable
define void @"_ZN98_$LT$alloc..vec..Vec$LT$T$GT$$u20$as$u20$alloc..vec..spec_from_iter..SpecFromIter$LT$T$C$I$GT$$GT$9from_iter17h7e287339a7855f7aE"(ptr sret([24 x i8]) align 8 %_0, ptr align 8 %iterator, ptr align 8 %0) unnamed_addr #1 {
start:
; call <alloc::vec::Vec<T> as alloc::vec::spec_from_iter_nested::SpecFromIterNested<T,I>>::from_iter
  call void @"_ZN111_$LT$alloc..vec..Vec$LT$T$GT$$u20$as$u20$alloc..vec..spec_from_iter_nested..SpecFromIterNested$LT$T$C$I$GT$$GT$9from_iter17h549752c212276cbaE"(ptr sret([24 x i8]) align 8 %_0, ptr align 8 %iterator, ptr align 8 %0)
  ret void
}

; <core::array::iter::IntoIter<T,_> as core::iter::traits::iterator::Iterator>::fold
; Function Attrs: inlinehint uwtable
define void @"_ZN99_$LT$core..array..iter..IntoIter$LT$T$C$_$GT$$u20$as$u20$core..iter..traits..iterator..Iterator$GT$4fold17h81e0f82241a328aaE"(ptr align 8 %self, ptr align 8 %fold) unnamed_addr #0 personality ptr @__CxxFrameHandler3 {
start:
  %_11 = alloca [40 x i8], align 8
  %f = alloca [24 x i8], align 8
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %f, ptr align 8 %fold, i64 24, i1 false)
  %data.0 = getelementptr inbounds i8, ptr %self, i64 16
  store ptr %data.0, ptr %_11, align 8
  %0 = getelementptr inbounds i8, ptr %_11, i64 8
  store i64 1, ptr %0, align 8
  %1 = getelementptr inbounds i8, ptr %_11, i64 16
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %1, ptr align 8 %f, i64 24, i1 false)
; invoke <core::ops::index_range::IndexRange as core::iter::traits::iterator::Iterator>::try_fold
  invoke void @"_ZN93_$LT$core..ops..index_range..IndexRange$u20$as$u20$core..iter..traits..iterator..Iterator$GT$8try_fold17h533f71010b1bd8daE"(ptr align 8 %self, ptr align 8 %_11)
          to label %bb4 unwind label %funclet_bb2

bb2:                                              ; preds = %funclet_bb2
; call core::ptr::drop_in_place<core::array::iter::IntoIter<(misanthropic::prompt::message::Role,&str),1_usize>>
  call void @"_ZN4core3ptr119drop_in_place$LT$core..array..iter..IntoIter$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$C$1_usize$GT$$GT$17h777d79445066cad3E"(ptr align 8 %self) #17 [ "funclet"(token %cleanuppad) ]
  cleanupret from %cleanuppad unwind to caller

funclet_bb2:                                      ; preds = %start
  %cleanuppad = cleanuppad within none []
  br label %bb2

bb4:                                              ; preds = %start
; call core::ptr::drop_in_place<core::array::iter::IntoIter<(misanthropic::prompt::message::Role,&str),1_usize>>
  call void @"_ZN4core3ptr119drop_in_place$LT$core..array..iter..IntoIter$LT$$LP$misanthropic..prompt..message..Role$C$$RF$str$RP$$C$1_usize$GT$$GT$17h777d79445066cad3E"(ptr align 8 %self)
  ret void
}

; <core::array::iter::IntoIter<T,_> as core::iter::traits::iterator::Iterator>::size_hint
; Function Attrs: inlinehint uwtable
define void @"_ZN99_$LT$core..array..iter..IntoIter$LT$T$C$_$GT$$u20$as$u20$core..iter..traits..iterator..Iterator$GT$9size_hint17h8b8ff9d275ad0b93E"(ptr sret([24 x i8]) align 8 %_0, ptr align 8 %self) unnamed_addr #0 {
start:
  %_5 = alloca [16 x i8], align 8
  %0 = getelementptr inbounds i8, ptr %self, i64 8
  %_6 = load i64, ptr %0, align 8
  %_7 = load i64, ptr %self, align 8
  %_4 = sub nuw i64 %_6, %_7
  %1 = getelementptr inbounds i8, ptr %_5, i64 8
  store i64 %_4, ptr %1, align 8
  store i64 1, ptr %_5, align 8
  store i64 %_4, ptr %_0, align 8
  %2 = load i64, ptr %_5, align 8
  %3 = getelementptr inbounds i8, ptr %_5, i64 8
  %4 = load i64, ptr %3, align 8
  %5 = getelementptr inbounds i8, ptr %_0, i64 8
  store i64 %2, ptr %5, align 8
  %6 = getelementptr inbounds i8, ptr %5, i64 8
  store i64 %4, ptr %6, align 8
  ret void
}

; misanthropic::send_message
; Function Attrs: uwtable
define void @_ZN12misanthropic12send_message17he141eda052a66029E(ptr sret([1656 x i8]) align 8 %_0, ptr align 1 %prompt_text.0, i64 %prompt_text.1) unnamed_addr #1 {
start:
  store ptr %prompt_text.0, ptr %_0, align 8
  %0 = getelementptr inbounds i8, ptr %_0, i64 8
  store i64 %prompt_text.1, ptr %0, align 8
  %1 = getelementptr inbounds i8, ptr %_0, i64 1648
  store i8 0, ptr %1, align 8
  ret void
}

; misanthropic::send_message::{{closure}}
; Function Attrs: inlinehint uwtable
define void @"_ZN12misanthropic12send_message28_$u7b$$u7b$closure$u7d$$u7d$17h836fccb0f7b966edE"(ptr sret([288 x i8]) align 8 %_0, ptr align 8 %0, ptr align 8 %_2) unnamed_addr #0 personality ptr @__CxxFrameHandler3 {
start:
  %e.i11 = alloca [48 x i8], align 8
  %e.i5 = alloca [8 x i8], align 8
  %e.i = alloca [64 x i8], align 8
  %_task_context = alloca [8 x i8], align 8
  %_22 = alloca [288 x i8], align 8
  %result = alloca [288 x i8], align 8
  %_16 = alloca [288 x i8], align 8
  %_13 = alloca [1192 x i8], align 8
  %_12 = alloca [1192 x i8], align 8
  %_11 = alloca [1 x i8], align 1
  %_10 = alloca [24 x i8], align 8
  %_9 = alloca [24 x i8], align 8
  %_8 = alloca [384 x i8], align 8
  %_7 = alloca [384 x i8], align 8
  %_5 = alloca [24 x i8], align 8
  %_4 = alloca [56 x i8], align 8
  %_1 = alloca [8 x i8], align 8
  store ptr %0, ptr %_1, align 8
  %_25 = load ptr, ptr %_1, align 8
  %1 = getelementptr inbounds i8, ptr %_25, i64 1648
  %2 = load i8, ptr %1, align 8
  %_24 = zext i8 %2 to i32
  switch i32 %_24, label %bb13 [
    i32 0, label %bb1
    i32 1, label %bb26
    i32 2, label %bb25
    i32 3, label %bb24
  ]

bb13:                                             ; preds = %start
  unreachable

bb1:                                              ; preds = %start
  store ptr %_2, ptr %_task_context, align 8
  %_26 = load ptr, ptr %_1, align 8
  %prompt_text.0 = load ptr, ptr %_26, align 8
  %3 = getelementptr inbounds i8, ptr %_26, i64 8
  %prompt_text.1 = load i64, ptr %3, align 8
; invoke <T as alloc::string::ToString>::to_string
  invoke void @"_ZN45_$LT$T$u20$as$u20$alloc..string..ToString$GT$9to_string17hc408f0da3fb7c564E"(ptr sret([24 x i8]) align 8 %_5, ptr align 1 @alloc_26137edaf0f0f9134544d99ec4a8facd, i64 13)
          to label %bb2 unwind label %funclet_bb23

bb26:                                             ; preds = %bb26, %start
  br i1 false, label %bb26, label %panic

bb25:                                             ; preds = %bb25, %start
  br i1 false, label %bb25, label %panic3

bb24:                                             ; preds = %start
  store ptr %_2, ptr %_task_context, align 8
  br label %bb10

bb23:                                             ; preds = %funclet_bb23
  %_41 = load ptr, ptr %_1, align 8
  %4 = getelementptr inbounds i8, ptr %_41, i64 1648
  store i8 2, ptr %4, align 8
  cleanupret from %cleanuppad unwind to caller

funclet_bb23:                                     ; preds = %funclet_bb4.i8, %bb22, %bb18, %bb2, %bb1
  %cleanuppad = cleanuppad within none []
  br label %bb23

bb2:                                              ; preds = %bb1
; invoke misanthropic::client::Client::new
  invoke void @_ZN12misanthropic6client6Client3new17h20d5e4a77330790fE(ptr sret([56 x i8]) align 8 %_4, ptr align 8 %_5)
          to label %bb3 unwind label %funclet_bb23

bb3:                                              ; preds = %bb2
  %_27 = load ptr, ptr %_1, align 8
  %5 = getelementptr inbounds i8, ptr %_27, i64 16
  %6 = load ptr, ptr %_4, align 8
  %7 = ptrtoint ptr %6 to i64
  %8 = icmp eq i64 %7, 0
  %_2.i6 = select i1 %8, i64 1, i64 0
  %9 = trunc nuw i64 %_2.i6 to i1
  br i1 %9, label %bb2.i7, label %"_ZN4core6result19Result$LT$T$C$E$GT$6unwrap17h5e5bc3400780928bE.exit"

bb2.i7:                                           ; preds = %bb3
  %10 = getelementptr inbounds i8, ptr %_4, i64 8
  %11 = load i64, ptr %10, align 8
  store i64 %11, ptr %e.i5, align 8
; invoke core::result::unwrap_failed
  invoke void @_ZN4core6result13unwrap_failed17h70751bb42e9051bdE(ptr align 1 @alloc_00ae4b301f7fab8ac9617c03fcbd7274, i64 43, ptr align 1 %e.i5, ptr align 8 @vtable.2, ptr align 8 @alloc_46404ed8a5ab13dcd083589d2953351c) #16
          to label %unreachable.i10 unwind label %funclet_bb4.i8

funclet_bb4.i8:                                   ; preds = %bb2.i7
  %cleanuppad.i9 = cleanuppad within none []
  cleanupret from %cleanuppad.i9 unwind label %funclet_bb23

unreachable.i10:                                  ; preds = %bb2.i7
  unreachable

"_ZN4core6result19Result$LT$T$C$E$GT$6unwrap17h5e5bc3400780928bE.exit": ; preds = %bb3
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %5, ptr align 8 %_4, i64 56, i1 false)
  br label %bb4

bb4:                                              ; preds = %"_ZN4core6result19Result$LT$T$C$E$GT$6unwrap17h5e5bc3400780928bE.exit"
; invoke <misanthropic::prompt::Prompt as core::default::Default>::default
  invoke void @"_ZN71_$LT$misanthropic..prompt..Prompt$u20$as$u20$core..default..Default$GT$7default17hc735de8aa47bdd8eE"(ptr sret([384 x i8]) align 8 %_8)
          to label %bb5 unwind label %funclet_bb22

bb22:                                             ; preds = %funclet_bb22
  %_40 = load ptr, ptr %_1, align 8
  %12 = getelementptr inbounds i8, ptr %_40, i64 16
; call core::ptr::drop_in_place<misanthropic::client::Client>
  call void @"_ZN4core3ptr49drop_in_place$LT$misanthropic..client..Client$GT$17h4d0925dfa4db6766E"(ptr align 8 %12) #17 [ "funclet"(token %cleanuppad1) ]
  cleanupret from %cleanuppad1 unwind label %funclet_bb23

funclet_bb22:                                     ; preds = %funclet_bb4.i, %.noexc, %bb21, %bb17, %bb5, %bb4
  %cleanuppad1 = cleanuppad within none []
  br label %bb22

bb5:                                              ; preds = %bb4
  store i8 0, ptr %_11, align 1
  %13 = load i8, ptr %_11, align 1
  store i8 %13, ptr %_10, align 8
  %14 = getelementptr inbounds i8, ptr %_10, i64 8
  store ptr %prompt_text.0, ptr %14, align 8
  %15 = getelementptr inbounds i8, ptr %14, i64 8
  store i64 %prompt_text.1, ptr %15, align 8
  %16 = getelementptr inbounds nuw { i8, [7 x i8], { ptr, i64 } }, ptr %_9, i64 0
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %16, ptr align 8 %_10, i64 24, i1 false)
; invoke misanthropic::prompt::Prompt::messages
  invoke void @_ZN12misanthropic6prompt6Prompt8messages17h4799d00569ae1beeE(ptr sret([384 x i8]) align 8 %_7, ptr align 8 %_8, ptr align 8 %_9)
          to label %bb6 unwind label %funclet_bb22

bb6:                                              ; preds = %bb5
  %_28 = load ptr, ptr %_1, align 8
  %17 = getelementptr inbounds i8, ptr %_28, i64 72
  %18 = load i64, ptr %_7, align 8
  %19 = icmp eq i64 %18, -9223372036854775808
  %_2.i = select i1 %19, i64 1, i64 0
  %20 = trunc nuw i64 %_2.i to i1
  br i1 %20, label %bb2.i, label %"_ZN4core6result19Result$LT$T$C$E$GT$6unwrap17h50de7294f50a9585E.exit"

bb2.i:                                            ; preds = %bb6
  %21 = getelementptr inbounds i8, ptr %_7, i64 8
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %e.i, ptr align 8 %21, i64 64, i1 false)
; invoke core::result::unwrap_failed
  invoke void @_ZN4core6result13unwrap_failed17h70751bb42e9051bdE(ptr align 1 @alloc_00ae4b301f7fab8ac9617c03fcbd7274, i64 43, ptr align 1 %e.i, ptr align 8 @vtable.1, ptr align 8 @alloc_da36a57fa65e0eec20bd7786fa7b529a) #16
          to label %unreachable.i unwind label %funclet_bb4.i

funclet_bb4.i:                                    ; preds = %bb2.i
  %cleanuppad.i = cleanuppad within none []
; invoke core::ptr::drop_in_place<misanthropic::prompt::TurnOrderError>
  invoke void @"_ZN4core3ptr57drop_in_place$LT$misanthropic..prompt..TurnOrderError$GT$17h7350f3462e7bc41cE"(ptr align 8 %e.i) #17 [ "funclet"(token %cleanuppad.i) ]
          to label %.noexc unwind label %funclet_bb22

.noexc:                                           ; preds = %funclet_bb4.i
  cleanupret from %cleanuppad.i unwind label %funclet_bb22

unreachable.i:                                    ; preds = %bb2.i
  unreachable

"_ZN4core6result19Result$LT$T$C$E$GT$6unwrap17h50de7294f50a9585E.exit": ; preds = %bb6
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %17, ptr align 8 %_7, i64 384, i1 false)
  br label %bb7

bb7:                                              ; preds = %"_ZN4core6result19Result$LT$T$C$E$GT$6unwrap17h50de7294f50a9585E.exit"
  %_29 = load ptr, ptr %_1, align 8
  %_14 = getelementptr inbounds i8, ptr %_29, i64 16
  %_30 = load ptr, ptr %_1, align 8
  %_15 = getelementptr inbounds i8, ptr %_30, i64 72
; invoke misanthropic::client::Client::message
  invoke void @_ZN12misanthropic6client6Client7message17h701907a354a7cb7eE(ptr sret([1192 x i8]) align 8 %_13, ptr align 8 %_14, ptr align 8 %_15)
          to label %bb8 unwind label %funclet_bb21

bb21:                                             ; preds = %funclet_bb21
  %_39 = load ptr, ptr %_1, align 8
  %22 = getelementptr inbounds i8, ptr %_39, i64 72
; call core::ptr::drop_in_place<misanthropic::prompt::Prompt>
  call void @"_ZN4core3ptr49drop_in_place$LT$misanthropic..prompt..Prompt$GT$17hd29181e141a17a3fE"(ptr align 8 %22) #17 [ "funclet"(token %cleanuppad2) ]
  cleanupret from %cleanuppad2 unwind label %funclet_bb22

funclet_bb21:                                     ; preds = %funclet_bb4.i14, %.noexc17, %bb20, %bb15, %bb8, %bb7
  %cleanuppad2 = cleanuppad within none []
  br label %bb21

bb8:                                              ; preds = %bb7
; invoke <F as core::future::into_future::IntoFuture>::into_future
  invoke void @"_ZN59_$LT$F$u20$as$u20$core..future..into_future..IntoFuture$GT$11into_future17hfa1302547ecb7869E"(ptr sret([1192 x i8]) align 8 %_12, ptr align 8 %_13)
          to label %bb9 unwind label %funclet_bb21

bb9:                                              ; preds = %bb8
  %_31 = load ptr, ptr %_1, align 8
  %23 = getelementptr inbounds i8, ptr %_31, i64 456
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %23, ptr align 8 %_12, i64 1192, i1 false)
  br label %bb10

bb10:                                             ; preds = %bb24, %bb9
  %_32 = load ptr, ptr %_1, align 8
  %_18 = getelementptr inbounds i8, ptr %_32, i64 456
  br label %bb11

panic:                                            ; preds = %bb26
; call core::panicking::panic_const::panic_const_async_fn_resumed
  call void @_ZN4core9panicking11panic_const28panic_const_async_fn_resumed17hf968b268d09f757eE(ptr align 8 @alloc_81fc3fdfb101020df5f12e76aae3afaa) #16
  unreachable

panic3:                                           ; preds = %bb25
; call core::panicking::panic_const::panic_const_async_fn_resumed_panic
  call void @_ZN4core9panicking11panic_const34panic_const_async_fn_resumed_panic17h3200919381e4fb33E(ptr align 8 @alloc_81fc3fdfb101020df5f12e76aae3afaa) #16
  unreachable

bb20:                                             ; preds = %funclet_bb20
  %_38 = load ptr, ptr %_1, align 8
  %24 = getelementptr inbounds i8, ptr %_38, i64 456
; call core::ptr::drop_in_place<misanthropic::client::Client::message<&misanthropic::prompt::Prompt>::{{closure}}>
  call void @"_ZN4core3ptr127drop_in_place$LT$misanthropic..client..Client..message$LT$$RF$misanthropic..prompt..Prompt$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$17ha0dad5de39c11c56E"(ptr align 8 %24) #17 [ "funclet"(token %cleanuppad4) ]
  cleanupret from %cleanuppad4 unwind label %funclet_bb21

funclet_bb20:                                     ; preds = %bb11
  %cleanuppad4 = cleanuppad within none []
  br label %bb20

bb11:                                             ; preds = %bb10
  %_19 = load ptr, ptr %_task_context, align 8
; invoke misanthropic::client::Client::message::{{closure}}
  invoke void @"_ZN12misanthropic6client6Client7message28_$u7b$$u7b$closure$u7d$$u7d$17h3a5afb124eca1ce5E"(ptr sret([288 x i8]) align 8 %_16, ptr align 8 %_18, ptr align 8 %_19)
          to label %bb12 unwind label %funclet_bb20

bb12:                                             ; preds = %bb11
  %25 = load i64, ptr %_16, align 8
  %26 = icmp eq i64 %25, 3
  %_20 = select i1 %26, i64 1, i64 0
  %27 = trunc nuw i64 %_20 to i1
  br i1 %27, label %bb14, label %bb15

bb14:                                             ; preds = %bb12
  store i64 2, ptr %_0, align 8
  %_33 = load ptr, ptr %_1, align 8
  %28 = getelementptr inbounds i8, ptr %_33, i64 1648
  store i8 3, ptr %28, align 8
  ret void

bb15:                                             ; preds = %bb12
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %result, ptr align 8 %_16, i64 288, i1 false)
  %_34 = load ptr, ptr %_1, align 8
  %29 = getelementptr inbounds i8, ptr %_34, i64 456
; invoke core::ptr::drop_in_place<misanthropic::client::Client::message<&misanthropic::prompt::Prompt>::{{closure}}>
  invoke void @"_ZN4core3ptr127drop_in_place$LT$misanthropic..client..Client..message$LT$$RF$misanthropic..prompt..Prompt$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$17ha0dad5de39c11c56E"(ptr align 8 %29)
          to label %bb16 unwind label %funclet_bb21

bb16:                                             ; preds = %bb15
  %30 = load i64, ptr %result, align 8
  %31 = icmp eq i64 %30, 2
  %_2.i12 = select i1 %31, i64 1, i64 0
  %32 = trunc nuw i64 %_2.i12 to i1
  br i1 %32, label %bb2.i13, label %"_ZN4core6result19Result$LT$T$C$E$GT$6unwrap17ha3da71368a295819E.exit"

bb2.i13:                                          ; preds = %bb16
  %33 = getelementptr inbounds i8, ptr %result, i64 8
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %e.i11, ptr align 8 %33, i64 48, i1 false)
; invoke core::result::unwrap_failed
  invoke void @_ZN4core6result13unwrap_failed17h70751bb42e9051bdE(ptr align 1 @alloc_00ae4b301f7fab8ac9617c03fcbd7274, i64 43, ptr align 1 %e.i11, ptr align 8 @vtable.0, ptr align 8 @alloc_89f2983d41b497819b93f33ed401a022) #16
          to label %unreachable.i16 unwind label %funclet_bb4.i14

funclet_bb4.i14:                                  ; preds = %bb2.i13
  %cleanuppad.i15 = cleanuppad within none []
; invoke core::ptr::drop_in_place<misanthropic::client::Error>
  invoke void @"_ZN4core3ptr48drop_in_place$LT$misanthropic..client..Error$GT$17h0315295c7eac22e8E"(ptr align 8 %e.i11) #17 [ "funclet"(token %cleanuppad.i15) ]
          to label %.noexc17 unwind label %funclet_bb21

.noexc17:                                         ; preds = %funclet_bb4.i14
  cleanupret from %cleanuppad.i15 unwind label %funclet_bb21

unreachable.i16:                                  ; preds = %bb2.i13
  unreachable

"_ZN4core6result19Result$LT$T$C$E$GT$6unwrap17ha3da71368a295819E.exit": ; preds = %bb16
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_22, ptr align 8 %result, i64 288, i1 false)
  br label %bb17

bb17:                                             ; preds = %"_ZN4core6result19Result$LT$T$C$E$GT$6unwrap17ha3da71368a295819E.exit"
  %_35 = load ptr, ptr %_1, align 8
  %34 = getelementptr inbounds i8, ptr %_35, i64 72
; invoke core::ptr::drop_in_place<misanthropic::prompt::Prompt>
  invoke void @"_ZN4core3ptr49drop_in_place$LT$misanthropic..prompt..Prompt$GT$17hd29181e141a17a3fE"(ptr align 8 %34)
          to label %bb18 unwind label %funclet_bb22

bb18:                                             ; preds = %bb17
  %_36 = load ptr, ptr %_1, align 8
  %35 = getelementptr inbounds i8, ptr %_36, i64 16
; invoke core::ptr::drop_in_place<misanthropic::client::Client>
  invoke void @"_ZN4core3ptr49drop_in_place$LT$misanthropic..client..Client$GT$17h4d0925dfa4db6766E"(ptr align 8 %35)
          to label %bb19 unwind label %funclet_bb23

bb19:                                             ; preds = %bb18
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_0, ptr align 8 %_22, i64 288, i1 false)
  %_37 = load ptr, ptr %_1, align 8
  %36 = getelementptr inbounds i8, ptr %_37, i64 1648
  store i8 1, ptr %36, align 8
  ret void
}

; misanthropic::stream_message
; Function Attrs: uwtable
define void @_ZN12misanthropic14stream_message17h62095ac6d371ed5bE(ptr sret([1656 x i8]) align 8 %_0, ptr align 1 %prompt_text.0, i64 %prompt_text.1) unnamed_addr #1 {
start:
  store ptr %prompt_text.0, ptr %_0, align 8
  %0 = getelementptr inbounds i8, ptr %_0, i64 8
  store i64 %prompt_text.1, ptr %0, align 8
  %1 = getelementptr inbounds i8, ptr %_0, i64 1648
  store i8 0, ptr %1, align 8
  ret void
}

; misanthropic::stream_message::{{closure}}
; Function Attrs: inlinehint uwtable
define void @"_ZN12misanthropic14stream_message28_$u7b$$u7b$closure$u7d$$u7d$17hf49a5f87b6de6820E"(ptr sret([360 x i8]) align 8 %_0, ptr align 8 %0, ptr align 8 %_2) unnamed_addr #0 personality ptr @__CxxFrameHandler3 {
start:
  %e.i12 = alloca [8 x i8], align 8
  %e.i5 = alloca [64 x i8], align 8
  %e.i = alloca [48 x i8], align 8
  %_task_context = alloca [8 x i8], align 8
  %_22 = alloca [360 x i8], align 8
  %result = alloca [360 x i8], align 8
  %_16 = alloca [360 x i8], align 8
  %_13 = alloca [1192 x i8], align 8
  %_12 = alloca [1192 x i8], align 8
  %_11 = alloca [1 x i8], align 1
  %_10 = alloca [24 x i8], align 8
  %_9 = alloca [24 x i8], align 8
  %_8 = alloca [384 x i8], align 8
  %_7 = alloca [384 x i8], align 8
  %_5 = alloca [24 x i8], align 8
  %_4 = alloca [56 x i8], align 8
  %_1 = alloca [8 x i8], align 8
  store ptr %0, ptr %_1, align 8
  %_25 = load ptr, ptr %_1, align 8
  %1 = getelementptr inbounds i8, ptr %_25, i64 1648
  %2 = load i8, ptr %1, align 8
  %_24 = zext i8 %2 to i32
  switch i32 %_24, label %bb13 [
    i32 0, label %bb1
    i32 1, label %bb26
    i32 2, label %bb25
    i32 3, label %bb24
  ]

bb13:                                             ; preds = %start
  unreachable

bb1:                                              ; preds = %start
  store ptr %_2, ptr %_task_context, align 8
  %_26 = load ptr, ptr %_1, align 8
  %prompt_text.0 = load ptr, ptr %_26, align 8
  %3 = getelementptr inbounds i8, ptr %_26, i64 8
  %prompt_text.1 = load i64, ptr %3, align 8
; invoke <T as alloc::string::ToString>::to_string
  invoke void @"_ZN45_$LT$T$u20$as$u20$alloc..string..ToString$GT$9to_string17hc408f0da3fb7c564E"(ptr sret([24 x i8]) align 8 %_5, ptr align 1 @alloc_26137edaf0f0f9134544d99ec4a8facd, i64 13)
          to label %bb2 unwind label %funclet_bb23

bb26:                                             ; preds = %bb26, %start
  br i1 false, label %bb26, label %panic

bb25:                                             ; preds = %bb25, %start
  br i1 false, label %bb25, label %panic3

bb24:                                             ; preds = %start
  store ptr %_2, ptr %_task_context, align 8
  br label %bb10

bb23:                                             ; preds = %funclet_bb23
  %_41 = load ptr, ptr %_1, align 8
  %4 = getelementptr inbounds i8, ptr %_41, i64 1648
  store i8 2, ptr %4, align 8
  cleanupret from %cleanuppad unwind to caller

funclet_bb23:                                     ; preds = %funclet_bb4.i15, %bb22, %bb18, %bb2, %bb1
  %cleanuppad = cleanuppad within none []
  br label %bb23

bb2:                                              ; preds = %bb1
; invoke misanthropic::client::Client::new
  invoke void @_ZN12misanthropic6client6Client3new17h20d5e4a77330790fE(ptr sret([56 x i8]) align 8 %_4, ptr align 8 %_5)
          to label %bb3 unwind label %funclet_bb23

bb3:                                              ; preds = %bb2
  %_27 = load ptr, ptr %_1, align 8
  %5 = getelementptr inbounds i8, ptr %_27, i64 16
  %6 = load ptr, ptr %_4, align 8
  %7 = ptrtoint ptr %6 to i64
  %8 = icmp eq i64 %7, 0
  %_2.i13 = select i1 %8, i64 1, i64 0
  %9 = trunc nuw i64 %_2.i13 to i1
  br i1 %9, label %bb2.i14, label %"_ZN4core6result19Result$LT$T$C$E$GT$6unwrap17h5e5bc3400780928bE.exit"

bb2.i14:                                          ; preds = %bb3
  %10 = getelementptr inbounds i8, ptr %_4, i64 8
  %11 = load i64, ptr %10, align 8
  store i64 %11, ptr %e.i12, align 8
; invoke core::result::unwrap_failed
  invoke void @_ZN4core6result13unwrap_failed17h70751bb42e9051bdE(ptr align 1 @alloc_00ae4b301f7fab8ac9617c03fcbd7274, i64 43, ptr align 1 %e.i12, ptr align 8 @vtable.2, ptr align 8 @alloc_9e6a6168768470af30921519e13425a0) #16
          to label %unreachable.i17 unwind label %funclet_bb4.i15

funclet_bb4.i15:                                  ; preds = %bb2.i14
  %cleanuppad.i16 = cleanuppad within none []
  cleanupret from %cleanuppad.i16 unwind label %funclet_bb23

unreachable.i17:                                  ; preds = %bb2.i14
  unreachable

"_ZN4core6result19Result$LT$T$C$E$GT$6unwrap17h5e5bc3400780928bE.exit": ; preds = %bb3
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %5, ptr align 8 %_4, i64 56, i1 false)
  br label %bb4

bb4:                                              ; preds = %"_ZN4core6result19Result$LT$T$C$E$GT$6unwrap17h5e5bc3400780928bE.exit"
; invoke <misanthropic::prompt::Prompt as core::default::Default>::default
  invoke void @"_ZN71_$LT$misanthropic..prompt..Prompt$u20$as$u20$core..default..Default$GT$7default17hc735de8aa47bdd8eE"(ptr sret([384 x i8]) align 8 %_8)
          to label %bb5 unwind label %funclet_bb22

bb22:                                             ; preds = %funclet_bb22
  %_40 = load ptr, ptr %_1, align 8
  %12 = getelementptr inbounds i8, ptr %_40, i64 16
; call core::ptr::drop_in_place<misanthropic::client::Client>
  call void @"_ZN4core3ptr49drop_in_place$LT$misanthropic..client..Client$GT$17h4d0925dfa4db6766E"(ptr align 8 %12) #17 [ "funclet"(token %cleanuppad1) ]
  cleanupret from %cleanuppad1 unwind label %funclet_bb23

funclet_bb22:                                     ; preds = %funclet_bb4.i8, %.noexc11, %bb21, %bb17, %bb5, %bb4
  %cleanuppad1 = cleanuppad within none []
  br label %bb22

bb5:                                              ; preds = %bb4
  store i8 0, ptr %_11, align 1
  %13 = load i8, ptr %_11, align 1
  store i8 %13, ptr %_10, align 8
  %14 = getelementptr inbounds i8, ptr %_10, i64 8
  store ptr %prompt_text.0, ptr %14, align 8
  %15 = getelementptr inbounds i8, ptr %14, i64 8
  store i64 %prompt_text.1, ptr %15, align 8
  %16 = getelementptr inbounds nuw { i8, [7 x i8], { ptr, i64 } }, ptr %_9, i64 0
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %16, ptr align 8 %_10, i64 24, i1 false)
; invoke misanthropic::prompt::Prompt::messages
  invoke void @_ZN12misanthropic6prompt6Prompt8messages17h4799d00569ae1beeE(ptr sret([384 x i8]) align 8 %_7, ptr align 8 %_8, ptr align 8 %_9)
          to label %bb6 unwind label %funclet_bb22

bb6:                                              ; preds = %bb5
  %_28 = load ptr, ptr %_1, align 8
  %17 = getelementptr inbounds i8, ptr %_28, i64 72
  %18 = load i64, ptr %_7, align 8
  %19 = icmp eq i64 %18, -9223372036854775808
  %_2.i6 = select i1 %19, i64 1, i64 0
  %20 = trunc nuw i64 %_2.i6 to i1
  br i1 %20, label %bb2.i7, label %"_ZN4core6result19Result$LT$T$C$E$GT$6unwrap17h50de7294f50a9585E.exit"

bb2.i7:                                           ; preds = %bb6
  %21 = getelementptr inbounds i8, ptr %_7, i64 8
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %e.i5, ptr align 8 %21, i64 64, i1 false)
; invoke core::result::unwrap_failed
  invoke void @_ZN4core6result13unwrap_failed17h70751bb42e9051bdE(ptr align 1 @alloc_00ae4b301f7fab8ac9617c03fcbd7274, i64 43, ptr align 1 %e.i5, ptr align 8 @vtable.1, ptr align 8 @alloc_5489c671b0b9b196c6445d24bdfea32b) #16
          to label %unreachable.i10 unwind label %funclet_bb4.i8

funclet_bb4.i8:                                   ; preds = %bb2.i7
  %cleanuppad.i9 = cleanuppad within none []
; invoke core::ptr::drop_in_place<misanthropic::prompt::TurnOrderError>
  invoke void @"_ZN4core3ptr57drop_in_place$LT$misanthropic..prompt..TurnOrderError$GT$17h7350f3462e7bc41cE"(ptr align 8 %e.i5) #17 [ "funclet"(token %cleanuppad.i9) ]
          to label %.noexc11 unwind label %funclet_bb22

.noexc11:                                         ; preds = %funclet_bb4.i8
  cleanupret from %cleanuppad.i9 unwind label %funclet_bb22

unreachable.i10:                                  ; preds = %bb2.i7
  unreachable

"_ZN4core6result19Result$LT$T$C$E$GT$6unwrap17h50de7294f50a9585E.exit": ; preds = %bb6
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %17, ptr align 8 %_7, i64 384, i1 false)
  br label %bb7

bb7:                                              ; preds = %"_ZN4core6result19Result$LT$T$C$E$GT$6unwrap17h50de7294f50a9585E.exit"
  %_29 = load ptr, ptr %_1, align 8
  %_14 = getelementptr inbounds i8, ptr %_29, i64 16
  %_30 = load ptr, ptr %_1, align 8
  %_15 = getelementptr inbounds i8, ptr %_30, i64 72
; invoke misanthropic::client::Client::stream
  invoke void @_ZN12misanthropic6client6Client6stream17ha46a03e894362e7cE(ptr sret([1192 x i8]) align 8 %_13, ptr align 8 %_14, ptr align 8 %_15)
          to label %bb8 unwind label %funclet_bb21

bb21:                                             ; preds = %funclet_bb21
  %_39 = load ptr, ptr %_1, align 8
  %22 = getelementptr inbounds i8, ptr %_39, i64 72
; call core::ptr::drop_in_place<misanthropic::prompt::Prompt>
  call void @"_ZN4core3ptr49drop_in_place$LT$misanthropic..prompt..Prompt$GT$17hd29181e141a17a3fE"(ptr align 8 %22) #17 [ "funclet"(token %cleanuppad2) ]
  cleanupret from %cleanuppad2 unwind label %funclet_bb22

funclet_bb21:                                     ; preds = %funclet_bb4.i, %.noexc, %bb20, %bb15, %bb8, %bb7
  %cleanuppad2 = cleanuppad within none []
  br label %bb21

bb8:                                              ; preds = %bb7
; invoke <F as core::future::into_future::IntoFuture>::into_future
  invoke void @"_ZN59_$LT$F$u20$as$u20$core..future..into_future..IntoFuture$GT$11into_future17h52a589b0e5dcff10E"(ptr sret([1192 x i8]) align 8 %_12, ptr align 8 %_13)
          to label %bb9 unwind label %funclet_bb21

bb9:                                              ; preds = %bb8
  %_31 = load ptr, ptr %_1, align 8
  %23 = getelementptr inbounds i8, ptr %_31, i64 456
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %23, ptr align 8 %_12, i64 1192, i1 false)
  br label %bb10

bb10:                                             ; preds = %bb24, %bb9
  %_32 = load ptr, ptr %_1, align 8
  %_18 = getelementptr inbounds i8, ptr %_32, i64 456
  br label %bb11

panic:                                            ; preds = %bb26
; call core::panicking::panic_const::panic_const_async_fn_resumed
  call void @_ZN4core9panicking11panic_const28panic_const_async_fn_resumed17hf968b268d09f757eE(ptr align 8 @alloc_6c9841a87da6571edecc93494eee6a2c) #16
  unreachable

panic3:                                           ; preds = %bb25
; call core::panicking::panic_const::panic_const_async_fn_resumed_panic
  call void @_ZN4core9panicking11panic_const34panic_const_async_fn_resumed_panic17h3200919381e4fb33E(ptr align 8 @alloc_6c9841a87da6571edecc93494eee6a2c) #16
  unreachable

bb20:                                             ; preds = %funclet_bb20
  %_38 = load ptr, ptr %_1, align 8
  %24 = getelementptr inbounds i8, ptr %_38, i64 456
; call core::ptr::drop_in_place<misanthropic::client::Client::stream<&misanthropic::prompt::Prompt>::{{closure}}>
  call void @"_ZN4core3ptr126drop_in_place$LT$misanthropic..client..Client..stream$LT$$RF$misanthropic..prompt..Prompt$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$17h9abc3d68019e8a21E"(ptr align 8 %24) #17 [ "funclet"(token %cleanuppad4) ]
  cleanupret from %cleanuppad4 unwind label %funclet_bb21

funclet_bb20:                                     ; preds = %bb11
  %cleanuppad4 = cleanuppad within none []
  br label %bb20

bb11:                                             ; preds = %bb10
  %_19 = load ptr, ptr %_task_context, align 8
; invoke misanthropic::client::Client::stream::{{closure}}
  invoke void @"_ZN12misanthropic6client6Client6stream28_$u7b$$u7b$closure$u7d$$u7d$17h14a7c3bdf53f5a4cE"(ptr sret([360 x i8]) align 8 %_16, ptr align 8 %_18, ptr align 8 %_19)
          to label %bb12 unwind label %funclet_bb20

bb12:                                             ; preds = %bb11
  %25 = load i64, ptr %_16, align 8
  %26 = icmp eq i64 %25, 19
  %_20 = select i1 %26, i64 1, i64 0
  %27 = trunc nuw i64 %_20 to i1
  br i1 %27, label %bb14, label %bb15

bb14:                                             ; preds = %bb12
  store i64 18, ptr %_0, align 8
  %_33 = load ptr, ptr %_1, align 8
  %28 = getelementptr inbounds i8, ptr %_33, i64 1648
  store i8 3, ptr %28, align 8
  ret void

bb15:                                             ; preds = %bb12
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %result, ptr align 8 %_16, i64 360, i1 false)
  %_34 = load ptr, ptr %_1, align 8
  %29 = getelementptr inbounds i8, ptr %_34, i64 456
; invoke core::ptr::drop_in_place<misanthropic::client::Client::stream<&misanthropic::prompt::Prompt>::{{closure}}>
  invoke void @"_ZN4core3ptr126drop_in_place$LT$misanthropic..client..Client..stream$LT$$RF$misanthropic..prompt..Prompt$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$17h9abc3d68019e8a21E"(ptr align 8 %29)
          to label %bb16 unwind label %funclet_bb21

bb16:                                             ; preds = %bb15
  %30 = load i64, ptr %result, align 8
  %31 = icmp eq i64 %30, 18
  %_2.i = select i1 %31, i64 1, i64 0
  %32 = trunc nuw i64 %_2.i to i1
  br i1 %32, label %bb2.i, label %"_ZN4core6result19Result$LT$T$C$E$GT$6unwrap17h384dbd13302b37a3E.exit"

bb2.i:                                            ; preds = %bb16
  %33 = getelementptr inbounds i8, ptr %result, i64 8
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %e.i, ptr align 8 %33, i64 48, i1 false)
; invoke core::result::unwrap_failed
  invoke void @_ZN4core6result13unwrap_failed17h70751bb42e9051bdE(ptr align 1 @alloc_00ae4b301f7fab8ac9617c03fcbd7274, i64 43, ptr align 1 %e.i, ptr align 8 @vtable.0, ptr align 8 @alloc_977023cf9969551de5b678c700ff8a31) #16
          to label %unreachable.i unwind label %funclet_bb4.i

funclet_bb4.i:                                    ; preds = %bb2.i
  %cleanuppad.i = cleanuppad within none []
; invoke core::ptr::drop_in_place<misanthropic::client::Error>
  invoke void @"_ZN4core3ptr48drop_in_place$LT$misanthropic..client..Error$GT$17h0315295c7eac22e8E"(ptr align 8 %e.i) #17 [ "funclet"(token %cleanuppad.i) ]
          to label %.noexc unwind label %funclet_bb21

.noexc:                                           ; preds = %funclet_bb4.i
  cleanupret from %cleanuppad.i unwind label %funclet_bb21

unreachable.i:                                    ; preds = %bb2.i
  unreachable

"_ZN4core6result19Result$LT$T$C$E$GT$6unwrap17h384dbd13302b37a3E.exit": ; preds = %bb16
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_22, ptr align 8 %result, i64 360, i1 false)
  br label %bb17

bb17:                                             ; preds = %"_ZN4core6result19Result$LT$T$C$E$GT$6unwrap17h384dbd13302b37a3E.exit"
  %_35 = load ptr, ptr %_1, align 8
  %34 = getelementptr inbounds i8, ptr %_35, i64 72
; invoke core::ptr::drop_in_place<misanthropic::prompt::Prompt>
  invoke void @"_ZN4core3ptr49drop_in_place$LT$misanthropic..prompt..Prompt$GT$17hd29181e141a17a3fE"(ptr align 8 %34)
          to label %bb18 unwind label %funclet_bb22

bb18:                                             ; preds = %bb17
  %_36 = load ptr, ptr %_1, align 8
  %35 = getelementptr inbounds i8, ptr %_36, i64 16
; invoke core::ptr::drop_in_place<misanthropic::client::Client>
  invoke void @"_ZN4core3ptr49drop_in_place$LT$misanthropic..client..Client$GT$17h4d0925dfa4db6766E"(ptr align 8 %35)
          to label %bb19 unwind label %funclet_bb23

bb19:                                             ; preds = %bb18
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_0, ptr align 8 %_22, i64 360, i1 false)
  %_37 = load ptr, ptr %_1, align 8
  %36 = getelementptr inbounds i8, ptr %_37, i64 1648
  store i8 1, ptr %36, align 8
  ret void
}

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: readwrite)
declare void @llvm.memcpy.p0.p0.i64(ptr noalias nocapture writeonly, ptr noalias nocapture readonly, i64, i1 immarg) #5

; core::panicking::panic_nounwind
; Function Attrs: cold noinline noreturn nounwind uwtable
declare void @_ZN4core9panicking14panic_nounwind17hb115782c8cb05dd0E(ptr align 1, i64) unnamed_addr #6

declare i32 @__CxxFrameHandler3(...) unnamed_addr #7

; alloc::raw_vec::RawVecInner<A>::with_capacity_in
; Function Attrs: inlinehint uwtable
declare { i64, ptr } @"_ZN5alloc7raw_vec20RawVecInner$LT$A$GT$16with_capacity_in17h25686f63b1e1ebd8E"(i64, i64, i64, ptr align 8) unnamed_addr #0

; core::ptr::drop_in_place<alloc::vec::Vec<misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>>>
; Function Attrs: uwtable
declare void @"_ZN4core3ptr129drop_in_place$LT$alloc..vec..Vec$LT$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$GT$$GT$17h80beb9192a52b8e4E"(ptr align 8) unnamed_addr #1

; core::panicking::panic_fmt
; Function Attrs: cold noinline noreturn uwtable
declare void @_ZN4core9panicking9panic_fmt17h6b7e0a7dad869f5aE(ptr align 8, ptr align 8) unnamed_addr #8

; misanthropic::client::Client::from_key
; Function Attrs: uwtable
declare void @_ZN12misanthropic6client6Client8from_key17he2bb25b445202670E(ptr sret([56 x i8]) align 8, ptr align 1) unnamed_addr #1

; serde_json::value::to_value
; Function Attrs: uwtable
declare void @_ZN10serde_json5value8to_value17h9da1b1abed4c459aE(ptr sret([72 x i8]) align 8, ptr align 8) unnamed_addr #1

; <core::result::Result<T,E> as core::ops::try_trait::Try>::branch
; Function Attrs: inlinehint uwtable
declare void @"_ZN79_$LT$core..result..Result$LT$T$C$E$GT$$u20$as$u20$core..ops..try_trait..Try$GT$6branch17h583b51c8ebd1bc09E"(ptr sret([72 x i8]) align 8, ptr align 8) unnamed_addr #0

; serde_json::value::index::<impl core::ops::index::IndexMut<I> for serde_json::value::Value>::index_mut
; Function Attrs: uwtable
declare align 8 ptr @"_ZN10serde_json5value5index90_$LT$impl$u20$core..ops..index..IndexMut$LT$I$GT$$u20$for$u20$serde_json..value..Value$GT$9index_mut17h714324fb407ccd14E"(ptr align 8, ptr align 1, i64, ptr align 8) unnamed_addr #1

; core::ptr::drop_in_place<serde_json::value::Value>
; Function Attrs: uwtable
declare void @"_ZN4core3ptr45drop_in_place$LT$serde_json..value..Value$GT$17h3b0bd242f80d52afE"(ptr align 8) unnamed_addr #1

; misanthropic::client::Client::request
; Function Attrs: uwtable
declare void @_ZN12misanthropic6client6Client7request17hbb050df3dac178b5E(ptr sret([1096 x i8]) align 8, ptr align 8, ptr align 8) unnamed_addr #1

; <F as core::future::into_future::IntoFuture>::into_future
; Function Attrs: uwtable
declare void @"_ZN59_$LT$F$u20$as$u20$core..future..into_future..IntoFuture$GT$11into_future17hf9d1281ba75964f2E"(ptr sret([1096 x i8]) align 8, ptr align 8) unnamed_addr #1

; core::panicking::panic_const::panic_const_async_fn_resumed
; Function Attrs: cold noinline noreturn uwtable
declare void @_ZN4core9panicking11panic_const28panic_const_async_fn_resumed17hf968b268d09f757eE(ptr align 8) unnamed_addr #8

; core::panicking::panic_const::panic_const_async_fn_resumed_panic
; Function Attrs: cold noinline noreturn uwtable
declare void @_ZN4core9panicking11panic_const34panic_const_async_fn_resumed_panic17h3200919381e4fb33E(ptr align 8) unnamed_addr #8

; misanthropic::client::Client::request::{{closure}}
; Function Attrs: inlinehint uwtable
declare void @"_ZN12misanthropic6client6Client7request28_$u7b$$u7b$closure$u7d$$u7d$17h0a8458d8f61a91e7E"(ptr sret([360 x i8]) align 8, ptr align 8, ptr align 8) unnamed_addr #0

; core::ptr::drop_in_place<misanthropic::client::Client::request<serde_json::value::Value>::{{closure}}>
; Function Attrs: uwtable
declare void @"_ZN4core3ptr119drop_in_place$LT$misanthropic..client..Client..request$LT$serde_json..value..Value$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$17h3f71628b587fadc0E"(ptr align 8) unnamed_addr #1

; <core::result::Result<T,E> as core::ops::try_trait::Try>::branch
; Function Attrs: inlinehint uwtable
declare void @"_ZN79_$LT$core..result..Result$LT$T$C$E$GT$$u20$as$u20$core..ops..try_trait..Try$GT$6branch17h2b8a3335c0e4df38E"(ptr sret([360 x i8]) align 8, ptr align 8) unnamed_addr #0

; core::ptr::drop_in_place<misanthropic::response::Response>
; Function Attrs: uwtable
declare void @"_ZN4core3ptr53drop_in_place$LT$misanthropic..response..Response$GT$17h91fab948d54fcbb3E"(ptr align 8) unnamed_addr #1

; misanthropic::prompt::Prompt::check_turn_order
; Function Attrs: uwtable
declare void @_ZN12misanthropic6prompt6Prompt16check_turn_order17h080470c1014aab72E(ptr sret([64 x i8]) align 8, ptr align 8) unnamed_addr #1

; <core::result::Result<T,E> as core::ops::try_trait::Try>::branch
; Function Attrs: inlinehint uwtable
declare void @"_ZN79_$LT$core..result..Result$LT$T$C$E$GT$$u20$as$u20$core..ops..try_trait..Try$GT$6branch17h6e787bdf34ff2ed1E"(ptr sret([64 x i8]) align 8, ptr align 8) unnamed_addr #0

; core::ptr::drop_in_place<misanthropic::prompt::Prompt>
; Function Attrs: uwtable
declare void @"_ZN4core3ptr49drop_in_place$LT$misanthropic..prompt..Prompt$GT$17hd29181e141a17a3fE"(ptr align 8) unnamed_addr #1

; <misanthropic::client::Error as core::convert::From<serde_json::error::Error>>::from
; Function Attrs: uwtable
declare void @"_ZN99_$LT$misanthropic..client..Error$u20$as$u20$core..convert..From$LT$serde_json..error..Error$GT$$GT$4from17h2e2843646521c289E"(ptr sret([48 x i8]) align 8, ptr align 8) unnamed_addr #1

; <serde_json::error::Error as core::fmt::Debug>::fmt
; Function Attrs: uwtable
declare zeroext i1 @"_ZN61_$LT$serde_json..error..Error$u20$as$u20$core..fmt..Debug$GT$3fmt17h353ee308a8389ff0E"(ptr align 8, ptr align 8) unnamed_addr #1

; core::fmt::num::imp::<impl core::fmt::Display for u16>::fmt
; Function Attrs: uwtable
declare zeroext i1 @"_ZN4core3fmt3num3imp52_$LT$impl$u20$core..fmt..Display$u20$for$u20$u16$GT$3fmt17h3fe79bb4702b6dbfE"(ptr align 2, ptr align 8) unnamed_addr #1

; core::fmt::num::<impl core::fmt::UpperHex for u16>::fmt
; Function Attrs: uwtable
declare zeroext i1 @"_ZN4core3fmt3num53_$LT$impl$u20$core..fmt..UpperHex$u20$for$u20$u16$GT$3fmt17h6629f1e170b83e4cE"(ptr align 2, ptr align 8) unnamed_addr #1

; core::fmt::num::<impl core::fmt::LowerHex for u16>::fmt
; Function Attrs: uwtable
declare zeroext i1 @"_ZN4core3fmt3num53_$LT$impl$u20$core..fmt..LowerHex$u20$for$u20$u16$GT$3fmt17hce7a69d038e0c81fE"(ptr align 2, ptr align 8) unnamed_addr #1

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare { i64, i1 } @llvm.uadd.with.overflow.i64(i64, i64) #9

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare i64 @llvm.ctpop.i64(i64) #9

; core::panicking::panic_cannot_unwind
; Function Attrs: cold minsize noinline noreturn nounwind optsize uwtable
declare void @_ZN4core9panicking19panic_cannot_unwind17h8a970db44b3fe0a2E() unnamed_addr #10

; core::ptr::drop_in_place<reqwest::async_impl::client::Client>
; Function Attrs: uwtable
declare void @"_ZN4core3ptr56drop_in_place$LT$reqwest..async_impl..client..Client$GT$17h323d6264c46a934eE"(ptr align 8) unnamed_addr #1

; core::ptr::drop_in_place<alloc::sync::Arc<misanthropic::key::unencrypted::Key>>
; Function Attrs: uwtable
declare void @"_ZN4core3ptr80drop_in_place$LT$alloc..sync..Arc$LT$misanthropic..key..unencrypted..Key$GT$$GT$17h56c2e12bbc997854E"(ptr align 8) unnamed_addr #1

; core::ptr::drop_in_place<alloc::sync::Arc<url::Url>>
; Function Attrs: uwtable
declare void @"_ZN4core3ptr53drop_in_place$LT$alloc..sync..Arc$LT$url..Url$GT$$GT$17hd7ac9074da8d1f83E"(ptr align 8) unnamed_addr #1

; core::ptr::drop_in_place<alloc::vec::set_len_on_drop::SetLenOnDrop>
; Function Attrs: uwtable
declare void @"_ZN4core3ptr62drop_in_place$LT$alloc..vec..set_len_on_drop..SetLenOnDrop$GT$17h000c414ff5ebd112E"(ptr align 8) unnamed_addr #1

; core::alloc::layout::Layout::is_size_align_valid
; Function Attrs: uwtable
declare zeroext i1 @_ZN4core5alloc6layout6Layout19is_size_align_valid17hc4a33d0890086caaE(i64, i64) unnamed_addr #1

; core::panicking::panic_const::panic_const_div_by_zero
; Function Attrs: cold noinline noreturn uwtable
declare void @_ZN4core9panicking11panic_const23panic_const_div_by_zero17h67a3eed2454b1972E(ptr align 8) unnamed_addr #8

; core::ptr::drop_in_place<misanthropic::client::Error>
; Function Attrs: uwtable
declare void @"_ZN4core3ptr48drop_in_place$LT$misanthropic..client..Error$GT$17h0315295c7eac22e8E"(ptr align 8) unnamed_addr #1

; core::result::unwrap_failed
; Function Attrs: cold noinline noreturn uwtable
declare void @_ZN4core6result13unwrap_failed17h70751bb42e9051bdE(ptr align 1, i64, ptr align 1, ptr align 8, ptr align 8) unnamed_addr #8

; core::ptr::drop_in_place<misanthropic::prompt::TurnOrderError>
; Function Attrs: uwtable
declare void @"_ZN4core3ptr57drop_in_place$LT$misanthropic..prompt..TurnOrderError$GT$17h7350f3462e7bc41cE"(ptr align 8) unnamed_addr #1

; <misanthropic::key::unencrypted::Key as core::convert::TryFrom<alloc::string::String>>::try_from
; Function Attrs: uwtable
declare void @"_ZN107_$LT$misanthropic..key..unencrypted..Key$u20$as$u20$core..convert..TryFrom$LT$alloc..string..String$GT$$GT$8try_from17he4808e8e9ebbcd65E"(ptr sret([112 x i8]) align 8, ptr align 8) unnamed_addr #1

; <str as core::fmt::Debug>::fmt
; Function Attrs: uwtable
declare zeroext i1 @"_ZN40_$LT$str$u20$as$u20$core..fmt..Debug$GT$3fmt17h03321ffdd769ea00E"(ptr align 1, i64, ptr align 8) unnamed_addr #1

; alloc::raw_vec::RawVecInner<A>::reserve::do_reserve_and_handle
; Function Attrs: cold uwtable
declare void @"_ZN5alloc7raw_vec20RawVecInner$LT$A$GT$7reserve21do_reserve_and_handle17hc13a237b4d39ded0E"(ptr align 8, i64, i64, i64, i64) unnamed_addr #11

; core::ptr::drop_in_place<core::option::Option<alloc::string::String>>
; Function Attrs: uwtable
declare void @"_ZN4core3ptr70drop_in_place$LT$core..option..Option$LT$alloc..string..String$GT$$GT$17hb91fbec02e242124E"(ptr align 8) unnamed_addr #1

; __rustc::__rust_alloc_zeroed
; Function Attrs: nounwind allockind("alloc,zeroed,aligned") allocsize(0) uwtable
declare noalias ptr @_RNvCs691rhTbG0Ee_7___rustc19___rust_alloc_zeroed(i64, i64 allocalign) unnamed_addr #12

; alloc::alloc::handle_alloc_error
; Function Attrs: cold minsize noreturn optsize uwtable
declare void @_ZN5alloc5alloc18handle_alloc_error17h5d20bbd2fe1a1ecaE(i64, i64) unnamed_addr #13

; __rustc::__rust_alloc
; Function Attrs: nounwind allockind("alloc,uninitialized,aligned") allocsize(0) uwtable
declare noalias ptr @_RNvCs691rhTbG0Ee_7___rustc12___rust_alloc(i64, i64 allocalign) unnamed_addr #14

; <&T as core::fmt::Debug>::fmt
; Function Attrs: uwtable
declare zeroext i1 @"_ZN42_$LT$$RF$T$u20$as$u20$core..fmt..Debug$GT$3fmt17h61ed4aaa3ee90e6fE"(ptr align 8, ptr align 8) unnamed_addr #1

; core::fmt::Formatter::debug_tuple_field1_finish
; Function Attrs: uwtable
declare zeroext i1 @_ZN4core3fmt9Formatter25debug_tuple_field1_finish17h62c9088540f0bcd6E(ptr align 8, ptr align 1, i64, ptr align 1, ptr align 8) unnamed_addr #1

; <&T as core::fmt::Debug>::fmt
; Function Attrs: uwtable
declare zeroext i1 @"_ZN42_$LT$$RF$T$u20$as$u20$core..fmt..Debug$GT$3fmt17h036e309bbd1bec74E"(ptr align 8, ptr align 8) unnamed_addr #1

; core::fmt::Formatter::debug_struct_field2_finish
; Function Attrs: uwtable
declare zeroext i1 @_ZN4core3fmt9Formatter26debug_struct_field2_finish17h3e899b71a0c5fe87E(ptr align 8, ptr align 1, i64, ptr align 1, i64, ptr align 1, ptr align 8, ptr align 1, i64, ptr align 1, ptr align 8) unnamed_addr #1

; <&T as core::fmt::Debug>::fmt
; Function Attrs: uwtable
declare zeroext i1 @"_ZN42_$LT$$RF$T$u20$as$u20$core..fmt..Debug$GT$3fmt17h0056c15810214fbaE"(ptr align 8, ptr align 8) unnamed_addr #1

; core::fmt::Formatter::debug_struct_field1_finish
; Function Attrs: uwtable
declare zeroext i1 @_ZN4core3fmt9Formatter26debug_struct_field1_finish17h31f5b3c155657224E(ptr align 8, ptr align 1, i64, ptr align 1, i64, ptr align 1, ptr align 8) unnamed_addr #1

; <&A as core::alloc::Allocator>::deallocate
; Function Attrs: inlinehint uwtable
declare void @"_ZN48_$LT$$RF$A$u20$as$u20$core..alloc..Allocator$GT$10deallocate17h107742a4aaca0c59E"(ptr align 8, ptr, i64, i64) unnamed_addr #0

; core::ptr::drop_in_place<alloc::string::String>
; Function Attrs: uwtable
declare void @"_ZN4core3ptr42drop_in_place$LT$alloc..string..String$GT$17hebd90fb8d5f940a3E"(ptr align 8) unnamed_addr #1

; <&T as core::fmt::Debug>::fmt
; Function Attrs: uwtable
declare zeroext i1 @"_ZN42_$LT$$RF$T$u20$as$u20$core..fmt..Debug$GT$3fmt17hb9427d2859f2466dE"(ptr align 8, ptr align 8) unnamed_addr #1

; <core::option::Option<T> as core::fmt::Debug>::fmt
; Function Attrs: inlinehint uwtable
declare zeroext i1 @"_ZN66_$LT$core..option..Option$LT$T$GT$$u20$as$u20$core..fmt..Debug$GT$3fmt17hbbb6cd418bb42cccE"(ptr align 2, ptr align 8) unnamed_addr #0

; <&T as core::fmt::Debug>::fmt
; Function Attrs: uwtable
declare zeroext i1 @"_ZN42_$LT$$RF$T$u20$as$u20$core..fmt..Debug$GT$3fmt17h4f173301853c4edbE"(ptr align 8, ptr align 8) unnamed_addr #1

; core::ptr::drop_in_place<misanthropic::prompt::message::RoleMessage<misanthropic::prompt::message::Role>>
; Function Attrs: uwtable
declare void @"_ZN4core3ptr106drop_in_place$LT$misanthropic..prompt..message..RoleMessage$LT$misanthropic..prompt..message..Role$GT$$GT$17hb0d3b39bf406e30bE"(ptr align 8) unnamed_addr #1

; <misanthropic::prompt::message::RoleMessage<R> as core::fmt::Debug>::fmt
; Function Attrs: inlinehint uwtable
declare zeroext i1 @"_ZN88_$LT$misanthropic..prompt..message..RoleMessage$LT$R$GT$$u20$as$u20$core..fmt..Debug$GT$3fmt17h834cd01f432b3e7dE"(ptr align 8, ptr align 8) unnamed_addr #0

; <&T as core::fmt::Debug>::fmt
; Function Attrs: uwtable
declare zeroext i1 @"_ZN42_$LT$$RF$T$u20$as$u20$core..fmt..Debug$GT$3fmt17h4e4609104daf91eeE"(ptr align 8, ptr align 8) unnamed_addr #1

; <&T as core::fmt::Debug>::fmt
; Function Attrs: uwtable
declare zeroext i1 @"_ZN42_$LT$$RF$T$u20$as$u20$core..fmt..Debug$GT$3fmt17ha721991b0ea53568E"(ptr align 8, ptr align 8) unnamed_addr #1

; <T as core::convert::Into<U>>::into
; Function Attrs: inlinehint uwtable
declare void @"_ZN50_$LT$T$u20$as$u20$core..convert..Into$LT$U$GT$$GT$4into17h8ea7934fb5035da2E"(ptr sret([208 x i8]) align 8, ptr align 1, i64, ptr align 8) unnamed_addr #0

; core::panicking::panic_misaligned_pointer_dereference
; Function Attrs: cold minsize noinline noreturn nounwind optsize uwtable
declare void @_ZN4core9panicking36panic_misaligned_pointer_dereference17hdbae00d467f272e7E(i64, i64, ptr align 8) unnamed_addr #10

; core::panicking::panic_null_pointer_dereference
; Function Attrs: cold minsize noinline noreturn nounwind optsize uwtable
declare void @_ZN4core9panicking30panic_null_pointer_dereference17h4567733e82a6ba35E(ptr align 8) unnamed_addr #10

; alloc::slice::<impl [T]>::into_vec
; Function Attrs: inlinehint uwtable
declare void @"_ZN5alloc5slice29_$LT$impl$u20$$u5b$T$u5d$$GT$8into_vec17h35e534e91cab947fE"(ptr sret([24 x i8]) align 8, ptr align 8, i64) unnamed_addr #0

; <alloc::boxed::Box<T,A> as core::ops::drop::Drop>::drop
; Function Attrs: inlinehint uwtable
declare void @"_ZN72_$LT$alloc..boxed..Box$LT$T$C$A$GT$$u20$as$u20$core..ops..drop..Drop$GT$4drop17h6693a0875a8ffe17E"(ptr align 8) unnamed_addr #0

; <core::ops::try_trait::NeverShortCircuit<T> as core::ops::try_trait::Try>::from_output
; Function Attrs: inlinehint uwtable
declare void @"_ZN94_$LT$core..ops..try_trait..NeverShortCircuit$LT$T$GT$$u20$as$u20$core..ops..try_trait..Try$GT$11from_output17h1e911e73c83835f8E"() unnamed_addr #0

; <core::ops::try_trait::NeverShortCircuit<T> as core::ops::try_trait::Try>::branch
; Function Attrs: inlinehint uwtable
declare void @"_ZN94_$LT$core..ops..try_trait..NeverShortCircuit$LT$T$GT$$u20$as$u20$core..ops..try_trait..Try$GT$6branch17hbbaf3ea4187b2a0cE"() unnamed_addr #0

; <core::ops::try_trait::NeverShortCircuit<T> as core::ops::try_trait::FromResidual<core::ops::try_trait::NeverShortCircuitResidual>>::from_residual
; Function Attrs: inlinehint uwtable
declare void @"_ZN158_$LT$core..ops..try_trait..NeverShortCircuit$LT$T$GT$$u20$as$u20$core..ops..try_trait..FromResidual$LT$core..ops..try_trait..NeverShortCircuitResidual$GT$$GT$13from_residual17h065e08a986c6abfcE"() unnamed_addr #0

; <T as alloc::string::ToString>::to_string
; Function Attrs: inlinehint uwtable
declare void @"_ZN45_$LT$T$u20$as$u20$alloc..string..ToString$GT$9to_string17hc408f0da3fb7c564E"(ptr sret([24 x i8]) align 8, ptr align 1, i64) unnamed_addr #0

; <misanthropic::prompt::Prompt as core::default::Default>::default
; Function Attrs: uwtable
declare void @"_ZN71_$LT$misanthropic..prompt..Prompt$u20$as$u20$core..default..Default$GT$7default17hc735de8aa47bdd8eE"(ptr sret([384 x i8]) align 8) unnamed_addr #1

; misanthropic::client::Client::message
; Function Attrs: uwtable
declare void @_ZN12misanthropic6client6Client7message17h701907a354a7cb7eE(ptr sret([1192 x i8]) align 8, ptr align 8, ptr align 8) unnamed_addr #1

; <F as core::future::into_future::IntoFuture>::into_future
; Function Attrs: uwtable
declare void @"_ZN59_$LT$F$u20$as$u20$core..future..into_future..IntoFuture$GT$11into_future17hfa1302547ecb7869E"(ptr sret([1192 x i8]) align 8, ptr align 8) unnamed_addr #1

; misanthropic::client::Client::message::{{closure}}
; Function Attrs: inlinehint uwtable
declare void @"_ZN12misanthropic6client6Client7message28_$u7b$$u7b$closure$u7d$$u7d$17h3a5afb124eca1ce5E"(ptr sret([288 x i8]) align 8, ptr align 8, ptr align 8) unnamed_addr #0

; core::ptr::drop_in_place<misanthropic::client::Client::message<&misanthropic::prompt::Prompt>::{{closure}}>
; Function Attrs: uwtable
declare void @"_ZN4core3ptr127drop_in_place$LT$misanthropic..client..Client..message$LT$$RF$misanthropic..prompt..Prompt$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$17ha0dad5de39c11c56E"(ptr align 8) unnamed_addr #1

attributes #0 = { inlinehint uwtable "target-cpu"="x86-64" "target-features"="+cx16,+sse3,+sahf" }
attributes #1 = { uwtable "target-cpu"="x86-64" "target-features"="+cx16,+sse3,+sahf" }
attributes #2 = { inlinehint nounwind uwtable "target-cpu"="x86-64" "target-features"="+cx16,+sse3,+sahf" }
attributes #3 = { alwaysinline uwtable "target-cpu"="x86-64" "target-features"="+cx16,+sse3,+sahf" }
attributes #4 = { noinline uwtable "target-cpu"="x86-64" "target-features"="+cx16,+sse3,+sahf" }
attributes #5 = { nocallback nofree nounwind willreturn memory(argmem: readwrite) }
attributes #6 = { cold noinline noreturn nounwind uwtable "target-cpu"="x86-64" "target-features"="+cx16,+sse3,+sahf" }
attributes #7 = { "target-cpu"="x86-64" }
attributes #8 = { cold noinline noreturn uwtable "target-cpu"="x86-64" "target-features"="+cx16,+sse3,+sahf" }
attributes #9 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }
attributes #10 = { cold minsize noinline noreturn nounwind optsize uwtable "target-cpu"="x86-64" "target-features"="+cx16,+sse3,+sahf" }
attributes #11 = { cold uwtable "target-cpu"="x86-64" "target-features"="+cx16,+sse3,+sahf" }
attributes #12 = { nounwind allockind("alloc,zeroed,aligned") allocsize(0) uwtable "alloc-family"="__rust_alloc" "target-cpu"="x86-64" "target-features"="+cx16,+sse3,+sahf" }
attributes #13 = { cold minsize noreturn optsize uwtable "target-cpu"="x86-64" "target-features"="+cx16,+sse3,+sahf" }
attributes #14 = { nounwind allockind("alloc,uninitialized,aligned") allocsize(0) uwtable "alloc-family"="__rust_alloc" "target-cpu"="x86-64" "target-features"="+cx16,+sse3,+sahf" }
attributes #15 = { noreturn nounwind }
attributes #16 = { noreturn }
attributes #17 = { cold }
attributes #18 = { nounwind }
attributes #19 = { cold noreturn nounwind }

!llvm.module.flags = !{!0}
!llvm.ident = !{!1}

!0 = !{i32 8, !"PIC Level", i32 2}
!1 = !{!"rustc version 1.88.0 (6b00bc388 2025-06-23)"}
