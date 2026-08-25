; ModuleID = '3le6au4stkq1hosz7ectc677v'
source_filename = "3le6au4stkq1hosz7ectc677v"
target datalayout = "e-m:o-i64:64-i128:128-n32:64-S128-Fn32"
target triple = "arm64-apple-macosx11.0.0"

@alloc_5958486b0931c00d4e434ff993635159 = private unnamed_addr constant <{ ptr, ptr, ptr, ptr }> <{ ptr @_ZN4core3ops8function6FnOnce9call_once17h06a514947178bc7dE, ptr @_ZN4core3ops8function6FnOnce9call_once17h5ed5c0ba2a3a4842E, ptr @_ZN4core3ops8function6FnOnce9call_once17h8d4fc8fdc42d99d7E, ptr @_ZN4core3ops8function6FnOnce9call_once17h9cf858b69c514052E }>, align 8
@alloc_746fb9887c04b6f04750a0d17a11f2e6 = private unnamed_addr constant <{ ptr, [8 x i8] }> <{ ptr @alloc_5958486b0931c00d4e434ff993635159, [8 x i8] zeroinitializer }>, align 8
@0 = private unnamed_addr constant <{ [8 x i8], [8 x i8] }> <{ [8 x i8] zeroinitializer, [8 x i8] undef }>, align 8
@1 = private unnamed_addr constant <{ [1 x i8], [23 x i8] }> <{ [1 x i8] c"\01", [23 x i8] undef }>, align 8
@alloc_6ad81882bf157ce64a1f79ee864cdd93 = private unnamed_addr constant <{ [18 x i8] }> <{ [18 x i8] c"http://example.com" }>, align 1
@alloc_f5ffd2fd1476bab43ad89fb40c72d0c5 = private unnamed_addr constant <{ [10 x i8] }> <{ [10 x i8] c"src/lib.rs" }>, align 1
@alloc_c212be42f4214727c4ffd84fb86993b8 = private unnamed_addr constant <{ ptr, [16 x i8] }> <{ ptr @alloc_f5ffd2fd1476bab43ad89fb40c72d0c5, [16 x i8] c"\0A\00\00\00\00\00\00\00\18\00\00\00\18\00\00\00" }>, align 8

; core::ops::function::FnOnce::call_once
; Function Attrs: inlinehint uwtable
define internal { ptr, ptr } @_ZN4core3ops8function6FnOnce9call_once17h06a514947178bc7dE(ptr %0) unnamed_addr #0 personality ptr @rust_eh_personality {
start:
  %1 = alloca [16 x i8], align 8
  %_2 = alloca [8 x i8], align 8
  %_1 = alloca [0 x i8], align 1
  store ptr %0, ptr %_2, align 8
  %2 = load ptr, ptr %_2, align 8
; invoke core::task::wake::RawWaker::NOOP::VTABLE::{{closure}}
  %3 = invoke { ptr, ptr } @"_ZN4core4task4wake8RawWaker4NOOP6VTABLE28_$u7b$$u7b$closure$u7d$$u7d$17haa1d125a3e502169E"(ptr align 1 %_1, ptr %2)
          to label %bb1 unwind label %cleanup

bb3:                                              ; preds = %cleanup
  %4 = load ptr, ptr %1, align 8
  %5 = getelementptr inbounds i8, ptr %1, i64 8
  %6 = load i32, ptr %5, align 8
  %7 = insertvalue { ptr, i32 } poison, ptr %4, 0
  %8 = insertvalue { ptr, i32 } %7, i32 %6, 1
  resume { ptr, i32 } %8

cleanup:                                          ; preds = %start
  %9 = landingpad { ptr, i32 }
          cleanup
  %10 = extractvalue { ptr, i32 } %9, 0
  %11 = extractvalue { ptr, i32 } %9, 1
  store ptr %10, ptr %1, align 8
  %12 = getelementptr inbounds i8, ptr %1, i64 8
  store i32 %11, ptr %12, align 8
  br label %bb3

bb1:                                              ; preds = %start
  %_0.0 = extractvalue { ptr, ptr } %3, 0
  %_0.1 = extractvalue { ptr, ptr } %3, 1
  %13 = insertvalue { ptr, ptr } poison, ptr %_0.0, 0
  %14 = insertvalue { ptr, ptr } %13, ptr %_0.1, 1
  ret { ptr, ptr } %14
}

; core::ops::function::FnOnce::call_once
; Function Attrs: inlinehint uwtable
define internal void @_ZN4core3ops8function6FnOnce9call_once17h5ed5c0ba2a3a4842E(ptr %0) unnamed_addr #0 personality ptr @rust_eh_personality {
start:
  %1 = alloca [16 x i8], align 8
  %_2 = alloca [8 x i8], align 8
  %_1 = alloca [0 x i8], align 1
  store ptr %0, ptr %_2, align 8
  %2 = load ptr, ptr %_2, align 8
; invoke core::task::wake::RawWaker::NOOP::VTABLE::{{closure}}
  invoke void @"_ZN4core4task4wake8RawWaker4NOOP6VTABLE28_$u7b$$u7b$closure$u7d$$u7d$17h87e51d6e4b3f024bE"(ptr align 1 %_1, ptr %2)
          to label %bb1 unwind label %cleanup

bb3:                                              ; preds = %cleanup
  %3 = load ptr, ptr %1, align 8
  %4 = getelementptr inbounds i8, ptr %1, i64 8
  %5 = load i32, ptr %4, align 8
  %6 = insertvalue { ptr, i32 } poison, ptr %3, 0
  %7 = insertvalue { ptr, i32 } %6, i32 %5, 1
  resume { ptr, i32 } %7

cleanup:                                          ; preds = %start
  %8 = landingpad { ptr, i32 }
          cleanup
  %9 = extractvalue { ptr, i32 } %8, 0
  %10 = extractvalue { ptr, i32 } %8, 1
  store ptr %9, ptr %1, align 8
  %11 = getelementptr inbounds i8, ptr %1, i64 8
  store i32 %10, ptr %11, align 8
  br label %bb3

bb1:                                              ; preds = %start
  ret void
}

; core::ops::function::FnOnce::call_once
; Function Attrs: inlinehint uwtable
define internal void @_ZN4core3ops8function6FnOnce9call_once17h8d4fc8fdc42d99d7E(ptr %0) unnamed_addr #0 personality ptr @rust_eh_personality {
start:
  %1 = alloca [16 x i8], align 8
  %_2 = alloca [8 x i8], align 8
  %_1 = alloca [0 x i8], align 1
  store ptr %0, ptr %_2, align 8
  %2 = load ptr, ptr %_2, align 8
; invoke core::task::wake::RawWaker::NOOP::VTABLE::{{closure}}
  invoke void @"_ZN4core4task4wake8RawWaker4NOOP6VTABLE28_$u7b$$u7b$closure$u7d$$u7d$17h8b9d2300db8f3c82E"(ptr align 1 %_1, ptr %2)
          to label %bb1 unwind label %cleanup

bb3:                                              ; preds = %cleanup
  %3 = load ptr, ptr %1, align 8
  %4 = getelementptr inbounds i8, ptr %1, i64 8
  %5 = load i32, ptr %4, align 8
  %6 = insertvalue { ptr, i32 } poison, ptr %3, 0
  %7 = insertvalue { ptr, i32 } %6, i32 %5, 1
  resume { ptr, i32 } %7

cleanup:                                          ; preds = %start
  %8 = landingpad { ptr, i32 }
          cleanup
  %9 = extractvalue { ptr, i32 } %8, 0
  %10 = extractvalue { ptr, i32 } %8, 1
  store ptr %9, ptr %1, align 8
  %11 = getelementptr inbounds i8, ptr %1, i64 8
  store i32 %10, ptr %11, align 8
  br label %bb3

bb1:                                              ; preds = %start
  ret void
}

; core::ops::function::FnOnce::call_once
; Function Attrs: inlinehint uwtable
define internal void @_ZN4core3ops8function6FnOnce9call_once17h9cf858b69c514052E(ptr %0) unnamed_addr #0 personality ptr @rust_eh_personality {
start:
  %1 = alloca [16 x i8], align 8
  %_2 = alloca [8 x i8], align 8
  %_1 = alloca [0 x i8], align 1
  store ptr %0, ptr %_2, align 8
  %2 = load ptr, ptr %_2, align 8
; invoke core::task::wake::RawWaker::NOOP::VTABLE::{{closure}}
  invoke void @"_ZN4core4task4wake8RawWaker4NOOP6VTABLE28_$u7b$$u7b$closure$u7d$$u7d$17h5a08161ca242d0a4E"(ptr align 1 %_1, ptr %2)
          to label %bb1 unwind label %cleanup

bb3:                                              ; preds = %cleanup
  %3 = load ptr, ptr %1, align 8
  %4 = getelementptr inbounds i8, ptr %1, i64 8
  %5 = load i32, ptr %4, align 8
  %6 = insertvalue { ptr, i32 } poison, ptr %3, 0
  %7 = insertvalue { ptr, i32 } %6, i32 %5, 1
  resume { ptr, i32 } %7

cleanup:                                          ; preds = %start
  %8 = landingpad { ptr, i32 }
          cleanup
  %9 = extractvalue { ptr, i32 } %8, 0
  %10 = extractvalue { ptr, i32 } %8, 1
  store ptr %9, ptr %1, align 8
  %11 = getelementptr inbounds i8, ptr %1, i64 8
  store i32 %10, ptr %11, align 8
  br label %bb3

bb1:                                              ; preds = %start
  ret void
}

; core::ptr::drop_in_place<reqwest::blocking::client::Client::request<&str>::{{closure}}>
; Function Attrs: uwtable
define void @"_ZN4core3ptr107drop_in_place$LT$reqwest..blocking..client..Client..request$LT$$RF$str$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$17hae451a43ecb240b7E"(ptr align 8 %_1) unnamed_addr #1 {
start:
; call core::ptr::drop_in_place<http::method::Method>
  call void @"_ZN4core3ptr41drop_in_place$LT$http..method..Method$GT$17hc2cb167d8c5499b3E"(ptr align 8 %_1)
  ret void
}

; core::ptr::drop_in_place<reqwest::async_impl::client::Client::request<&str>::{{closure}}>
; Function Attrs: uwtable
define void @"_ZN4core3ptr109drop_in_place$LT$reqwest..async_impl..client..Client..request$LT$$RF$str$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$17hc774a5abb6841bc6E"(ptr align 8 %_1) unnamed_addr #1 {
start:
; call core::ptr::drop_in_place<http::method::Method>
  call void @"_ZN4core3ptr41drop_in_place$LT$http..method..Method$GT$17hc2cb167d8c5499b3E"(ptr align 8 %_1)
  ret void
}

; core::ptr::drop_in_place<core::result::Result<reqwest::blocking::response::Response,reqwest::error::Error>>
; Function Attrs: uwtable
define void @"_ZN4core3ptr110drop_in_place$LT$core..result..Result$LT$reqwest..blocking..response..Response$C$reqwest..error..Error$GT$$GT$17hb5bbef2a0caa3090E"(ptr align 8 %_1) unnamed_addr #1 {
start:
  %0 = load i64, ptr %_1, align 8
  %1 = icmp eq i64 %0, 3
  %_2 = select i1 %1, i64 1, i64 0
  %2 = icmp eq i64 %_2, 0
  br i1 %2, label %bb2, label %bb3

bb2:                                              ; preds = %start
; call core::ptr::drop_in_place<reqwest::blocking::response::Response>
  call void @"_ZN4core3ptr58drop_in_place$LT$reqwest..blocking..response..Response$GT$17h76f84ec9abd7170cE"(ptr align 8 %_1)
  br label %bb1

bb3:                                              ; preds = %start
  %3 = getelementptr inbounds i8, ptr %_1, i64 8
; call core::ptr::drop_in_place<reqwest::error::Error>
  call void @"_ZN4core3ptr42drop_in_place$LT$reqwest..error..Error$GT$17h27d879affa0191e1E"(ptr align 8 %3)
  br label %bb1

bb1:                                              ; preds = %bb3, %bb2
  ret void
}

; core::ptr::drop_in_place<reqwest::blocking::response::Response>
; Function Attrs: uwtable
define void @"_ZN4core3ptr58drop_in_place$LT$reqwest..blocking..response..Response$GT$17h76f84ec9abd7170cE"(ptr align 8 %_1) unnamed_addr #1 personality ptr @rust_eh_personality {
start:
  %0 = alloca [16 x i8], align 8
; invoke core::ptr::drop_in_place<reqwest::async_impl::response::Response>
  invoke void @"_ZN4core3ptr60drop_in_place$LT$reqwest..async_impl..response..Response$GT$17h9433d2fbf2bf5649E"(ptr align 8 %_1)
          to label %bb6 unwind label %cleanup

bb4:                                              ; preds = %cleanup
  %1 = getelementptr inbounds i8, ptr %_1, i64 152
; invoke core::ptr::drop_in_place<core::option::Option<core::pin::Pin<alloc::boxed::Box<dyn futures_io::if_std::AsyncRead+core::marker::Send+core::marker::Sync>>>>
  invoke void @"_ZN4core3ptr179drop_in_place$LT$core..option..Option$LT$core..pin..Pin$LT$alloc..boxed..Box$LT$dyn$u20$futures_io..if_std..AsyncRead$u2b$core..marker..Send$u2b$core..marker..Sync$GT$$GT$$GT$$GT$17h41ac32546485c774E"(ptr align 8 %1) #6
          to label %bb3 unwind label %terminate

cleanup:                                          ; preds = %start
  %2 = landingpad { ptr, i32 }
          cleanup
  %3 = extractvalue { ptr, i32 } %2, 0
  %4 = extractvalue { ptr, i32 } %2, 1
  store ptr %3, ptr %0, align 8
  %5 = getelementptr inbounds i8, ptr %0, i64 8
  store i32 %4, ptr %5, align 8
  br label %bb4

bb6:                                              ; preds = %start
  %6 = getelementptr inbounds i8, ptr %_1, i64 152
; invoke core::ptr::drop_in_place<core::option::Option<core::pin::Pin<alloc::boxed::Box<dyn futures_io::if_std::AsyncRead+core::marker::Send+core::marker::Sync>>>>
  invoke void @"_ZN4core3ptr179drop_in_place$LT$core..option..Option$LT$core..pin..Pin$LT$alloc..boxed..Box$LT$dyn$u20$futures_io..if_std..AsyncRead$u2b$core..marker..Send$u2b$core..marker..Sync$GT$$GT$$GT$$GT$17h41ac32546485c774E"(ptr align 8 %6)
          to label %bb5 unwind label %cleanup1

bb3:                                              ; preds = %bb4, %cleanup1
  %7 = getelementptr inbounds i8, ptr %_1, i64 168
; invoke core::ptr::drop_in_place<reqwest::blocking::client::KeepCoreThreadAlive>
  invoke void @"_ZN4core3ptr67drop_in_place$LT$reqwest..blocking..client..KeepCoreThreadAlive$GT$17he03b48440cc42b6cE"(ptr align 8 %7) #6
          to label %bb1 unwind label %terminate

cleanup1:                                         ; preds = %bb6
  %8 = landingpad { ptr, i32 }
          cleanup
  %9 = extractvalue { ptr, i32 } %8, 0
  %10 = extractvalue { ptr, i32 } %8, 1
  store ptr %9, ptr %0, align 8
  %11 = getelementptr inbounds i8, ptr %0, i64 8
  store i32 %10, ptr %11, align 8
  br label %bb3

bb5:                                              ; preds = %bb6
  %12 = getelementptr inbounds i8, ptr %_1, i64 168
; call core::ptr::drop_in_place<reqwest::blocking::client::KeepCoreThreadAlive>
  call void @"_ZN4core3ptr67drop_in_place$LT$reqwest..blocking..client..KeepCoreThreadAlive$GT$17he03b48440cc42b6cE"(ptr align 8 %12)
  ret void

terminate:                                        ; preds = %bb3, %bb4
  %13 = landingpad { ptr, i32 }
          filter [0 x ptr] zeroinitializer
  %14 = extractvalue { ptr, i32 } %13, 0
  %15 = extractvalue { ptr, i32 } %13, 1
; call core::panicking::panic_in_cleanup
  call void @_ZN4core9panicking16panic_in_cleanup17hb960b8c5dea287d4E() #7
  unreachable

bb1:                                              ; preds = %bb3
  %16 = load ptr, ptr %0, align 8
  %17 = getelementptr inbounds i8, ptr %0, i64 8
  %18 = load i32, ptr %17, align 8
  %19 = insertvalue { ptr, i32 } poison, ptr %16, 0
  %20 = insertvalue { ptr, i32 } %19, i32 %18, 1
  resume { ptr, i32 } %20
}

; core::ptr::drop_in_place<raw_http_reqwest::do_send::{{closure}}>
; Function Attrs: uwtable
define void @"_ZN4core3ptr75drop_in_place$LT$raw_http_reqwest..do_send..$u7b$$u7b$closure$u7d$$u7d$$GT$17hfb9f22acc9bc8cb4E"(ptr align 8 %_1) unnamed_addr #1 personality ptr @rust_eh_personality {
start:
  %0 = alloca [16 x i8], align 8
  %1 = getelementptr inbounds i8, ptr %_1, i64 24
  %2 = load i8, ptr %1, align 8
  %_30 = zext i8 %2 to i32
  switch i32 %_30, label %bb15 [
    i32 0, label %bb11
    i32 3, label %bb14
  ]

bb15:                                             ; preds = %start
  ret void

bb11:                                             ; preds = %start
  ret void

bb14:                                             ; preds = %start
  %3 = getelementptr inbounds i8, ptr %_1, i64 8
; invoke core::ptr::drop_in_place<reqwest::async_impl::client::Pending>
  invoke void @"_ZN4core3ptr57drop_in_place$LT$reqwest..async_impl..client..Pending$GT$17ha0c4d20cc150ed16E"(ptr align 8 %3)
          to label %bb2 unwind label %cleanup

bb7:                                              ; preds = %cleanup
; invoke core::ptr::drop_in_place<reqwest::async_impl::client::Client>
  invoke void @"_ZN4core3ptr56drop_in_place$LT$reqwest..async_impl..client..Client$GT$17he5f1fedd540d99e6E"(ptr align 8 %_1) #6
          to label %bb9 unwind label %terminate

cleanup:                                          ; preds = %bb14
  %4 = landingpad { ptr, i32 }
          cleanup
  %5 = extractvalue { ptr, i32 } %4, 0
  %6 = extractvalue { ptr, i32 } %4, 1
  store ptr %5, ptr %0, align 8
  %7 = getelementptr inbounds i8, ptr %0, i64 8
  store i32 %6, ptr %7, align 8
  br label %bb7

bb2:                                              ; preds = %bb14
; invoke core::ptr::drop_in_place<reqwest::async_impl::client::Client>
  invoke void @"_ZN4core3ptr56drop_in_place$LT$reqwest..async_impl..client..Client$GT$17he5f1fedd540d99e6E"(ptr align 8 %_1)
          to label %bb4 unwind label %cleanup1

bb9:                                              ; preds = %bb7, %cleanup1
  %8 = load ptr, ptr %0, align 8
  %9 = getelementptr inbounds i8, ptr %0, i64 8
  %10 = load i32, ptr %9, align 8
  %11 = insertvalue { ptr, i32 } poison, ptr %8, 0
  %12 = insertvalue { ptr, i32 } %11, i32 %10, 1
  resume { ptr, i32 } %12

cleanup1:                                         ; preds = %bb2
  %13 = landingpad { ptr, i32 }
          cleanup
  %14 = extractvalue { ptr, i32 } %13, 0
  %15 = extractvalue { ptr, i32 } %13, 1
  store ptr %14, ptr %0, align 8
  %16 = getelementptr inbounds i8, ptr %0, i64 8
  store i32 %15, ptr %16, align 8
  br label %bb9

bb4:                                              ; preds = %bb2
  ret void

terminate:                                        ; preds = %bb7
  %17 = landingpad { ptr, i32 }
          filter [0 x ptr] zeroinitializer
  %18 = extractvalue { ptr, i32 } %17, 0
  %19 = extractvalue { ptr, i32 } %17, 1
; call core::panicking::panic_in_cleanup
  call void @_ZN4core9panicking16panic_in_cleanup17hb960b8c5dea287d4E() #7
  unreachable
}

; core::task::wake::Waker::noop
; Function Attrs: inlinehint uwtable
define internal align 8 ptr @_ZN4core4task4wake5Waker4noop17h3a2266c439c47f60E() unnamed_addr #0 {
start:
  ret ptr @alloc_746fb9887c04b6f04750a0d17a11f2e6
}

; core::task::wake::Context::from_waker
; Function Attrs: inlinehint uwtable
define internal void @_ZN4core4task4wake7Context10from_waker17hb12f415282b2e7d6E(ptr sret([32 x i8]) align 8 %_0, ptr align 8 %waker) unnamed_addr #0 {
start:
  store ptr %waker, ptr %_0, align 8
  %0 = getelementptr inbounds i8, ptr %_0, i64 8
  store ptr %waker, ptr %0, align 8
  %1 = load ptr, ptr @0, align 8
  %2 = load ptr, ptr getelementptr inbounds (i8, ptr @0, i64 8), align 8
  %3 = getelementptr inbounds i8, ptr %_0, i64 16
  store ptr %1, ptr %3, align 8
  %4 = getelementptr inbounds i8, ptr %3, i64 8
  store ptr %2, ptr %4, align 8
  ret void
}

; core::task::wake::RawWaker::NOOP::VTABLE::{{closure}}
; Function Attrs: inlinehint uwtable
define void @"_ZN4core4task4wake8RawWaker4NOOP6VTABLE28_$u7b$$u7b$closure$u7d$$u7d$17h5a08161ca242d0a4E"(ptr align 1 %_1, ptr %_2) unnamed_addr #0 {
start:
  ret void
}

; core::task::wake::RawWaker::NOOP::VTABLE::{{closure}}
; Function Attrs: inlinehint uwtable
define void @"_ZN4core4task4wake8RawWaker4NOOP6VTABLE28_$u7b$$u7b$closure$u7d$$u7d$17h87e51d6e4b3f024bE"(ptr align 1 %_1, ptr %_2) unnamed_addr #0 {
start:
  ret void
}

; core::task::wake::RawWaker::NOOP::VTABLE::{{closure}}
; Function Attrs: inlinehint uwtable
define void @"_ZN4core4task4wake8RawWaker4NOOP6VTABLE28_$u7b$$u7b$closure$u7d$$u7d$17h8b9d2300db8f3c82E"(ptr align 1 %_1, ptr %_2) unnamed_addr #0 {
start:
  ret void
}

; core::task::wake::RawWaker::NOOP::VTABLE::{{closure}}
; Function Attrs: inlinehint uwtable
define { ptr, ptr } @"_ZN4core4task4wake8RawWaker4NOOP6VTABLE28_$u7b$$u7b$closure$u7d$$u7d$17haa1d125a3e502169E"(ptr align 1 %_1, ptr %_2) unnamed_addr #0 {
start:
  ret { ptr, ptr } { ptr @alloc_5958486b0931c00d4e434ff993635159, ptr null }
}

; core::result::Result<T,E>::map
; Function Attrs: inlinehint uwtable
define void @"_ZN4core6result19Result$LT$T$C$E$GT$3map17h270c2059c7014b2aE"(ptr sret([304 x i8]) align 8 %_0, ptr align 8 %self, ptr align 8 %op) unnamed_addr #0 {
start:
  %_7 = alloca [88 x i8], align 8
  %_6 = alloca [24 x i8], align 8
  %_5 = alloca [304 x i8], align 8
  %t = alloca [88 x i8], align 8
  %0 = load i64, ptr %self, align 8
  %1 = icmp eq i64 %0, -9223372036854775808
  %_3 = select i1 %1, i64 1, i64 0
  %2 = icmp eq i64 %_3, 0
  br i1 %2, label %bb3, label %bb2

bb3:                                              ; preds = %start
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %t, ptr align 8 %self, i64 88, i1 false)
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_6, ptr align 8 %op, i64 24, i1 false)
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_7, ptr align 8 %t, i64 88, i1 false)
; call reqwest::blocking::client::Client::request::{{closure}}
  call void @"_ZN7reqwest8blocking6client6Client7request28_$u7b$$u7b$closure$u7d$$u7d$17hc2a440fd2e38b4cdE"(ptr sret([304 x i8]) align 8 %_5, ptr align 8 %_6, ptr align 8 %_7)
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_0, ptr align 8 %_5, i64 304, i1 false)
  br label %bb5

bb2:                                              ; preds = %start
  %3 = getelementptr inbounds i8, ptr %self, i64 8
  %e = load ptr, ptr %3, align 8
  %4 = getelementptr inbounds i8, ptr %_0, i64 8
  store ptr %e, ptr %4, align 8
  store i64 2, ptr %_0, align 8
; call core::ptr::drop_in_place<reqwest::blocking::client::Client::request<&str>::{{closure}}>
  call void @"_ZN4core3ptr107drop_in_place$LT$reqwest..blocking..client..Client..request$LT$$RF$str$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$17hae451a43ecb240b7E"(ptr align 8 %op)
  br label %bb5

bb5:                                              ; preds = %bb2, %bb3
  ret void

bb1:                                              ; No predecessors!
  unreachable
}

; core::result::Result<T,E>::map
; Function Attrs: inlinehint uwtable
define void @"_ZN4core6result19Result$LT$T$C$E$GT$3map17hfccab47d5cbad6c0E"(ptr sret([264 x i8]) align 8 %_0, ptr align 8 %self, ptr align 8 %op) unnamed_addr #0 {
start:
  %_7 = alloca [88 x i8], align 8
  %_6 = alloca [24 x i8], align 8
  %_5 = alloca [264 x i8], align 8
  %t = alloca [88 x i8], align 8
  %0 = load i64, ptr %self, align 8
  %1 = icmp eq i64 %0, -9223372036854775808
  %_3 = select i1 %1, i64 1, i64 0
  %2 = icmp eq i64 %_3, 0
  br i1 %2, label %bb3, label %bb2

bb3:                                              ; preds = %start
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %t, ptr align 8 %self, i64 88, i1 false)
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_6, ptr align 8 %op, i64 24, i1 false)
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_7, ptr align 8 %t, i64 88, i1 false)
; call reqwest::async_impl::client::Client::request::{{closure}}
  call void @"_ZN7reqwest10async_impl6client6Client7request28_$u7b$$u7b$closure$u7d$$u7d$17ha7c8c51f04c0649bE"(ptr sret([264 x i8]) align 8 %_5, ptr align 8 %_6, ptr align 8 %_7)
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_0, ptr align 8 %_5, i64 264, i1 false)
  br label %bb5

bb2:                                              ; preds = %start
  %3 = getelementptr inbounds i8, ptr %self, i64 8
  %e = load ptr, ptr %3, align 8
  %4 = getelementptr inbounds i8, ptr %_0, i64 8
  store ptr %e, ptr %4, align 8
  store i64 2, ptr %_0, align 8
; call core::ptr::drop_in_place<reqwest::async_impl::client::Client::request<&str>::{{closure}}>
  call void @"_ZN4core3ptr109drop_in_place$LT$reqwest..async_impl..client..Client..request$LT$$RF$str$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$17hc774a5abb6841bc6E"(ptr align 8 %op)
  br label %bb5

bb5:                                              ; preds = %bb2, %bb3
  ret void

bb1:                                              ; No predecessors!
  unreachable
}

; http::extensions::Extensions::new
; Function Attrs: inlinehint uwtable
define internal align 8 ptr @_ZN4http10extensions10Extensions3new17h05f98a5947ab68e6E() unnamed_addr #0 {
start:
  %_1 = alloca [8 x i8], align 8
  store ptr null, ptr %_1, align 8
  %_0 = load ptr, ptr %_1, align 8
  ret ptr %_0
}

; http::header::map::HeaderMap::new
; Function Attrs: inlinehint uwtable
define internal void @_ZN4http6header3map9HeaderMap3new17h03ce434ef301be4aE(ptr sret([96 x i8]) align 8 %_0) unnamed_addr #0 {
start:
; call <http::header::map::HeaderMap<T> as core::default::Default>::default
  call void @"_ZN80_$LT$http..header..map..HeaderMap$LT$T$GT$$u20$as$u20$core..default..Default$GT$7default17h5832afa0117982a9E"(ptr sret([96 x i8]) align 8 %_0)
  ret void
}

; <F as core::future::into_future::IntoFuture>::into_future
; Function Attrs: uwtable
define { i64, ptr } @"_ZN59_$LT$F$u20$as$u20$core..future..into_future..IntoFuture$GT$11into_future17h32613fa1e2907a15E"(i64 %self.0, ptr %self.1) unnamed_addr #1 {
start:
  %0 = insertvalue { i64, ptr } poison, i64 %self.0, 0
  %1 = insertvalue { i64, ptr } %0, ptr %self.1, 1
  ret { i64, ptr } %1
}

; <&mut T as core::ops::deref::DerefMut>::deref_mut
; Function Attrs: uwtable
define align 8 ptr @"_ZN60_$LT$$RF$mut$u20$T$u20$as$u20$core..ops..deref..DerefMut$GT$9deref_mut17h0bd9729e2744b2cdE"(ptr align 8 %self) unnamed_addr #1 {
start:
  %_0 = load ptr, ptr %self, align 8
  ret ptr %_0
}

; <http::version::Version as core::default::Default>::default
; Function Attrs: inlinehint uwtable
define internal i8 @"_ZN65_$LT$http..version..Version$u20$as$u20$core..default..Default$GT$7default17ha16eacb55b6063e6E"() unnamed_addr #0 {
start:
  ret i8 2
}

; <reqwest::blocking::client::Client as core::clone::Clone>::clone
; Function Attrs: inlinehint uwtable
define internal void @"_ZN72_$LT$reqwest..blocking..client..Client$u20$as$u20$core..clone..Clone$GT$5clone17hc12bcae7255e5c21E"(ptr sret([24 x i8]) align 8 %_0, ptr align 8 %self) unnamed_addr #0 {
start:
  %_2 = alloca [24 x i8], align 8
; call <reqwest::blocking::client::ClientHandle as core::clone::Clone>::clone
  call void @"_ZN78_$LT$reqwest..blocking..client..ClientHandle$u20$as$u20$core..clone..Clone$GT$5clone17hd60e55a3de5bba2cE"(ptr sret([24 x i8]) align 8 %_2, ptr align 8 %self)
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_0, ptr align 8 %_2, i64 24, i1 false)
  ret void
}

; <reqwest::blocking::client::Timeout as core::clone::Clone>::clone
; Function Attrs: inlinehint uwtable
define internal { i64, i32 } @"_ZN73_$LT$reqwest..blocking..client..Timeout$u20$as$u20$core..clone..Clone$GT$5clone17hddb562882c4855a6E"(ptr align 8 %self) unnamed_addr #0 {
start:
  %_0.0 = load i64, ptr %self, align 8
  %0 = getelementptr inbounds i8, ptr %self, i64 8
  %_0.1 = load i32, ptr %0, align 8
  %1 = insertvalue { i64, i32 } poison, i64 %_0.0, 0
  %2 = insertvalue { i64, i32 } %1, i32 %_0.1, 1
  ret { i64, i32 } %2
}

; <reqwest::async_impl::client::Client as core::clone::Clone>::clone
; Function Attrs: inlinehint uwtable
define internal ptr @"_ZN74_$LT$reqwest..async_impl..client..Client$u20$as$u20$core..clone..Clone$GT$5clone17h35609387001ffa17E"(ptr align 8 %self) unnamed_addr #0 {
start:
; call <alloc::sync::Arc<T,A> as core::clone::Clone>::clone
  %_2 = call ptr @"_ZN68_$LT$alloc..sync..Arc$LT$T$C$A$GT$$u20$as$u20$core..clone..Clone$GT$5clone17h33ccda2c0e054e36E"(ptr align 8 %self)
  ret ptr %_2
}

; <reqwest::blocking::client::ClientHandle as core::clone::Clone>::clone
; Function Attrs: inlinehint uwtable
define internal void @"_ZN78_$LT$reqwest..blocking..client..ClientHandle$u20$as$u20$core..clone..Clone$GT$5clone17hd60e55a3de5bba2cE"(ptr sret([24 x i8]) align 8 %_0, ptr align 8 %self) unnamed_addr #0 {
start:
  %_3 = getelementptr inbounds i8, ptr %self, i64 8
; call <reqwest::blocking::client::Timeout as core::clone::Clone>::clone
  %0 = call { i64, i32 } @"_ZN73_$LT$reqwest..blocking..client..Timeout$u20$as$u20$core..clone..Clone$GT$5clone17hddb562882c4855a6E"(ptr align 8 %_3)
  %_2.0 = extractvalue { i64, i32 } %0, 0
  %_2.1 = extractvalue { i64, i32 } %0, 1
; call <alloc::sync::Arc<T,A> as core::clone::Clone>::clone
  %_4 = call ptr @"_ZN68_$LT$alloc..sync..Arc$LT$T$C$A$GT$$u20$as$u20$core..clone..Clone$GT$5clone17hed23787606f596e0E"(ptr align 8 %self)
  %1 = getelementptr inbounds i8, ptr %_0, i64 8
  store i64 %_2.0, ptr %1, align 8
  %2 = getelementptr inbounds i8, ptr %1, i64 8
  store i32 %_2.1, ptr %2, align 8
  store ptr %_4, ptr %_0, align 8
  ret void
}

; reqwest::async_impl::client::Client::get
; Function Attrs: uwtable
define void @_ZN7reqwest10async_impl6client6Client3get17hb005ac5db594dc27E(ptr sret([272 x i8]) align 8 %_0, ptr align 8 %self, ptr align 1 %url.0, i64 %url.1) unnamed_addr #1 {
start:
  %0 = alloca [24 x i8], align 8
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %0, ptr align 8 @1, i64 24, i1 false)
; call reqwest::async_impl::client::Client::request
  call void @_ZN7reqwest10async_impl6client6Client7request17h404e17a252cfd051E(ptr sret([272 x i8]) align 8 %_0, ptr align 8 %self, ptr align 8 %0, ptr align 1 %url.0, i64 %url.1)
  ret void
}

; reqwest::async_impl::client::Client::request
; Function Attrs: uwtable
define void @_ZN7reqwest10async_impl6client6Client7request17h404e17a252cfd051E(ptr sret([272 x i8]) align 8 %_0, ptr align 8 %self, ptr align 8 %method, ptr align 1 %url.0, i64 %url.1) unnamed_addr #1 personality ptr @rust_eh_personality {
start:
  %0 = alloca [16 x i8], align 8
  %_10 = alloca [1 x i8], align 1
  %_9 = alloca [1 x i8], align 1
  %_8 = alloca [264 x i8], align 8
  %_6 = alloca [24 x i8], align 8
  %_5 = alloca [88 x i8], align 8
  %req = alloca [264 x i8], align 8
  store i8 0, ptr %_10, align 1
  store i8 0, ptr %_9, align 1
  store i8 1, ptr %_10, align 1
; invoke <&str as reqwest::into_url::IntoUrlSealed>::into_url
  invoke void @"_ZN60_$LT$$RF$str$u20$as$u20$reqwest..into_url..IntoUrlSealed$GT$8into_url17he89b26eee4e66eeaE"(ptr sret([88 x i8]) align 8 %_5, ptr align 1 %url.0, i64 %url.1)
          to label %bb1 unwind label %cleanup

bb9:                                              ; preds = %bb6, %bb7, %cleanup
  %1 = load i8, ptr %_10, align 1
  %2 = trunc i8 %1 to i1
  br i1 %2, label %bb8, label %bb5

cleanup:                                          ; preds = %bb1, %start
  %3 = landingpad { ptr, i32 }
          cleanup
  %4 = extractvalue { ptr, i32 } %3, 0
  %5 = extractvalue { ptr, i32 } %3, 1
  store ptr %4, ptr %0, align 8
  %6 = getelementptr inbounds i8, ptr %0, i64 8
  store i32 %5, ptr %6, align 8
  br label %bb9

bb1:                                              ; preds = %start
  store i8 0, ptr %_10, align 1
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_6, ptr align 8 %method, i64 24, i1 false)
; invoke core::result::Result<T,E>::map
  invoke void @"_ZN4core6result19Result$LT$T$C$E$GT$3map17hfccab47d5cbad6c0E"(ptr sret([264 x i8]) align 8 %req, ptr align 8 %_5, ptr align 8 %_6)
          to label %bb2 unwind label %cleanup

bb2:                                              ; preds = %bb1
  store i8 1, ptr %_9, align 1
; invoke <reqwest::async_impl::client::Client as core::clone::Clone>::clone
  %_7 = invoke ptr @"_ZN74_$LT$reqwest..async_impl..client..Client$u20$as$u20$core..clone..Clone$GT$5clone17h35609387001ffa17E"(ptr align 8 %self)
          to label %bb3 unwind label %cleanup1

bb7:                                              ; preds = %cleanup1
  %7 = load i8, ptr %_9, align 1
  %8 = trunc i8 %7 to i1
  br i1 %8, label %bb6, label %bb9

cleanup1:                                         ; preds = %bb3, %bb2
  %9 = landingpad { ptr, i32 }
          cleanup
  %10 = extractvalue { ptr, i32 } %9, 0
  %11 = extractvalue { ptr, i32 } %9, 1
  store ptr %10, ptr %0, align 8
  %12 = getelementptr inbounds i8, ptr %0, i64 8
  store i32 %11, ptr %12, align 8
  br label %bb7

bb3:                                              ; preds = %bb2
  store i8 0, ptr %_9, align 1
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_8, ptr align 8 %req, i64 264, i1 false)
; invoke reqwest::async_impl::request::RequestBuilder::new
  invoke void @_ZN7reqwest10async_impl7request14RequestBuilder3new17h0e12ddd9f5f32108E(ptr sret([272 x i8]) align 8 %_0, ptr %_7, ptr align 8 %_8)
          to label %bb4 unwind label %cleanup1

bb4:                                              ; preds = %bb3
  store i8 0, ptr %_9, align 1
  ret void

bb6:                                              ; preds = %bb7
; invoke core::ptr::drop_in_place<core::result::Result<reqwest::async_impl::request::Request,reqwest::error::Error>>
  invoke void @"_ZN4core3ptr110drop_in_place$LT$core..result..Result$LT$reqwest..async_impl..request..Request$C$reqwest..error..Error$GT$$GT$17he27e495364365f84E"(ptr align 8 %req) #6
          to label %bb9 unwind label %terminate

terminate:                                        ; preds = %bb8, %bb6
  %13 = landingpad { ptr, i32 }
          filter [0 x ptr] zeroinitializer
  %14 = extractvalue { ptr, i32 } %13, 0
  %15 = extractvalue { ptr, i32 } %13, 1
; call core::panicking::panic_in_cleanup
  call void @_ZN4core9panicking16panic_in_cleanup17hb960b8c5dea287d4E() #7
  unreachable

bb5:                                              ; preds = %bb8, %bb9
  %16 = load ptr, ptr %0, align 8
  %17 = getelementptr inbounds i8, ptr %0, i64 8
  %18 = load i32, ptr %17, align 8
  %19 = insertvalue { ptr, i32 } poison, ptr %16, 0
  %20 = insertvalue { ptr, i32 } %19, i32 %18, 1
  resume { ptr, i32 } %20

bb8:                                              ; preds = %bb9
; invoke core::ptr::drop_in_place<http::method::Method>
  invoke void @"_ZN4core3ptr41drop_in_place$LT$http..method..Method$GT$17hc2cb167d8c5499b3E"(ptr align 8 %method) #6
          to label %bb5 unwind label %terminate
}

; reqwest::async_impl::client::Client::request::{{closure}}
; Function Attrs: inlinehint uwtable
define void @"_ZN7reqwest10async_impl6client6Client7request28_$u7b$$u7b$closure$u7d$$u7d$17ha7c8c51f04c0649bE"(ptr sret([264 x i8]) align 8 %_0, ptr align 8 %_1, ptr align 8 %url) unnamed_addr #0 {
start:
  %_3 = alloca [24 x i8], align 8
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_3, ptr align 8 %_1, i64 24, i1 false)
; call reqwest::async_impl::request::Request::new
  call void @_ZN7reqwest10async_impl7request7Request3new17hba466ca910ece236E(ptr sret([264 x i8]) align 8 %_0, ptr align 8 %_3, ptr align 8 %url)
  ret void
}

; reqwest::async_impl::request::Request::new
; Function Attrs: inlinehint uwtable
define internal void @_ZN7reqwest10async_impl7request7Request3new17hba466ca910ece236E(ptr sret([264 x i8]) align 8 %_0, ptr align 8 %method, ptr align 8 %url) unnamed_addr #0 personality ptr @rust_eh_personality {
start:
  %0 = alloca [16 x i8], align 8
  %_6 = alloca [40 x i8], align 8
  %_5 = alloca [96 x i8], align 8
  %_4 = alloca [88 x i8], align 8
  %_3 = alloca [24 x i8], align 8
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_3, ptr align 8 %method, i64 24, i1 false)
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_4, ptr align 8 %url, i64 88, i1 false)
; invoke http::header::map::HeaderMap::new
  invoke void @_ZN4http6header3map9HeaderMap3new17h03ce434ef301be4aE(ptr sret([96 x i8]) align 8 %_5)
          to label %bb1 unwind label %cleanup

bb6:                                              ; preds = %bb5, %cleanup
; invoke core::ptr::drop_in_place<url::Url>
  invoke void @"_ZN4core3ptr29drop_in_place$LT$url..Url$GT$17hc00100ec9bd43773E"(ptr align 8 %_4) #6
          to label %bb7 unwind label %terminate

cleanup:                                          ; preds = %start
  %1 = landingpad { ptr, i32 }
          cleanup
  %2 = extractvalue { ptr, i32 } %1, 0
  %3 = extractvalue { ptr, i32 } %1, 1
  store ptr %2, ptr %0, align 8
  %4 = getelementptr inbounds i8, ptr %0, i64 8
  store i32 %3, ptr %4, align 8
  br label %bb6

bb1:                                              ; preds = %start
  store i64 0, ptr %_6, align 8
; invoke <http::version::Version as core::default::Default>::default
  %_7 = invoke i8 @"_ZN65_$LT$http..version..Version$u20$as$u20$core..default..Default$GT$7default17ha16eacb55b6063e6E"()
          to label %bb2 unwind label %cleanup1

bb4:                                              ; preds = %cleanup1
; invoke core::ptr::drop_in_place<core::option::Option<reqwest::async_impl::body::Body>>
  invoke void @"_ZN4core3ptr80drop_in_place$LT$core..option..Option$LT$reqwest..async_impl..body..Body$GT$$GT$17h47dd78234e6ecd91E"(ptr align 8 %_6) #6
          to label %bb5 unwind label %terminate

cleanup1:                                         ; preds = %bb2, %bb1
  %5 = landingpad { ptr, i32 }
          cleanup
  %6 = extractvalue { ptr, i32 } %5, 0
  %7 = extractvalue { ptr, i32 } %5, 1
  store ptr %6, ptr %0, align 8
  %8 = getelementptr inbounds i8, ptr %0, i64 8
  store i32 %7, ptr %8, align 8
  br label %bb4

bb2:                                              ; preds = %bb1
; invoke http::extensions::Extensions::new
  %_8 = invoke align 8 ptr @_ZN4http10extensions10Extensions3new17h05f98a5947ab68e6E()
          to label %bb3 unwind label %cleanup1

bb3:                                              ; preds = %bb2
  %9 = getelementptr inbounds i8, ptr %_0, i64 224
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %9, ptr align 8 %_3, i64 24, i1 false)
  %10 = getelementptr inbounds i8, ptr %_0, i64 136
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %10, ptr align 8 %_4, i64 88, i1 false)
  %11 = getelementptr inbounds i8, ptr %_0, i64 40
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %11, ptr align 8 %_5, i64 96, i1 false)
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_0, ptr align 8 %_6, i64 40, i1 false)
  %12 = getelementptr inbounds i8, ptr %_0, i64 256
  store i8 %_7, ptr %12, align 8
  %13 = getelementptr inbounds i8, ptr %_0, i64 248
  store ptr %_8, ptr %13, align 8
  ret void

terminate:                                        ; preds = %bb7, %bb6, %bb5, %bb4
  %14 = landingpad { ptr, i32 }
          filter [0 x ptr] zeroinitializer
  %15 = extractvalue { ptr, i32 } %14, 0
  %16 = extractvalue { ptr, i32 } %14, 1
; call core::panicking::panic_in_cleanup
  call void @_ZN4core9panicking16panic_in_cleanup17hb960b8c5dea287d4E() #7
  unreachable

bb5:                                              ; preds = %bb4
; invoke core::ptr::drop_in_place<http::header::map::HeaderMap>
  invoke void @"_ZN4core3ptr49drop_in_place$LT$http..header..map..HeaderMap$GT$17h97924f40e575a3f7E"(ptr align 8 %_5) #6
          to label %bb6 unwind label %terminate

bb7:                                              ; preds = %bb6
; invoke core::ptr::drop_in_place<http::method::Method>
  invoke void @"_ZN4core3ptr41drop_in_place$LT$http..method..Method$GT$17hc2cb167d8c5499b3E"(ptr align 8 %_3) #6
          to label %bb8 unwind label %terminate

bb8:                                              ; preds = %bb7
  %17 = load ptr, ptr %0, align 8
  %18 = getelementptr inbounds i8, ptr %0, i64 8
  %19 = load i32, ptr %18, align 8
  %20 = insertvalue { ptr, i32 } poison, ptr %17, 0
  %21 = insertvalue { ptr, i32 } %20, i32 %19, 1
  resume { ptr, i32 } %21
}

; reqwest::blocking::client::Client::get
; Function Attrs: uwtable
define void @_ZN7reqwest8blocking6client6Client3get17h1d67d1645865cd36E(ptr sret([328 x i8]) align 8 %_0, ptr align 8 %self, ptr align 1 %url.0, i64 %url.1) unnamed_addr #1 {
start:
  %0 = alloca [24 x i8], align 8
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %0, ptr align 8 @1, i64 24, i1 false)
; call reqwest::blocking::client::Client::request
  call void @_ZN7reqwest8blocking6client6Client7request17hb1aa4c020bd917c9E(ptr sret([328 x i8]) align 8 %_0, ptr align 8 %self, ptr align 8 %0, ptr align 1 %url.0, i64 %url.1)
  ret void
}

; reqwest::blocking::client::Client::request
; Function Attrs: uwtable
define void @_ZN7reqwest8blocking6client6Client7request17hb1aa4c020bd917c9E(ptr sret([328 x i8]) align 8 %_0, ptr align 8 %self, ptr align 8 %method, ptr align 1 %url.0, i64 %url.1) unnamed_addr #1 personality ptr @rust_eh_personality {
start:
  %0 = alloca [16 x i8], align 8
  %_10 = alloca [1 x i8], align 1
  %_9 = alloca [1 x i8], align 1
  %_8 = alloca [304 x i8], align 8
  %_7 = alloca [24 x i8], align 8
  %_6 = alloca [24 x i8], align 8
  %_5 = alloca [88 x i8], align 8
  %req = alloca [304 x i8], align 8
  store i8 0, ptr %_10, align 1
  store i8 0, ptr %_9, align 1
  store i8 1, ptr %_10, align 1
; invoke <&str as reqwest::into_url::IntoUrlSealed>::into_url
  invoke void @"_ZN60_$LT$$RF$str$u20$as$u20$reqwest..into_url..IntoUrlSealed$GT$8into_url17he89b26eee4e66eeaE"(ptr sret([88 x i8]) align 8 %_5, ptr align 1 %url.0, i64 %url.1)
          to label %bb1 unwind label %cleanup

bb9:                                              ; preds = %bb6, %bb7, %cleanup
  %1 = load i8, ptr %_10, align 1
  %2 = trunc i8 %1 to i1
  br i1 %2, label %bb8, label %bb5

cleanup:                                          ; preds = %bb1, %start
  %3 = landingpad { ptr, i32 }
          cleanup
  %4 = extractvalue { ptr, i32 } %3, 0
  %5 = extractvalue { ptr, i32 } %3, 1
  store ptr %4, ptr %0, align 8
  %6 = getelementptr inbounds i8, ptr %0, i64 8
  store i32 %5, ptr %6, align 8
  br label %bb9

bb1:                                              ; preds = %start
  store i8 0, ptr %_10, align 1
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_6, ptr align 8 %method, i64 24, i1 false)
; invoke core::result::Result<T,E>::map
  invoke void @"_ZN4core6result19Result$LT$T$C$E$GT$3map17h270c2059c7014b2aE"(ptr sret([304 x i8]) align 8 %req, ptr align 8 %_5, ptr align 8 %_6)
          to label %bb2 unwind label %cleanup

bb2:                                              ; preds = %bb1
  store i8 1, ptr %_9, align 1
; invoke <reqwest::blocking::client::Client as core::clone::Clone>::clone
  invoke void @"_ZN72_$LT$reqwest..blocking..client..Client$u20$as$u20$core..clone..Clone$GT$5clone17hc12bcae7255e5c21E"(ptr sret([24 x i8]) align 8 %_7, ptr align 8 %self)
          to label %bb3 unwind label %cleanup1

bb7:                                              ; preds = %cleanup1
  %7 = load i8, ptr %_9, align 1
  %8 = trunc i8 %7 to i1
  br i1 %8, label %bb6, label %bb9

cleanup1:                                         ; preds = %bb3, %bb2
  %9 = landingpad { ptr, i32 }
          cleanup
  %10 = extractvalue { ptr, i32 } %9, 0
  %11 = extractvalue { ptr, i32 } %9, 1
  store ptr %10, ptr %0, align 8
  %12 = getelementptr inbounds i8, ptr %0, i64 8
  store i32 %11, ptr %12, align 8
  br label %bb7

bb3:                                              ; preds = %bb2
  store i8 0, ptr %_9, align 1
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_8, ptr align 8 %req, i64 304, i1 false)
; invoke reqwest::blocking::request::RequestBuilder::new
  invoke void @_ZN7reqwest8blocking7request14RequestBuilder3new17hd92757e2ea46310fE(ptr sret([328 x i8]) align 8 %_0, ptr align 8 %_7, ptr align 8 %_8)
          to label %bb4 unwind label %cleanup1

bb4:                                              ; preds = %bb3
  store i8 0, ptr %_9, align 1
  ret void

bb6:                                              ; preds = %bb7
; invoke core::ptr::drop_in_place<core::result::Result<reqwest::blocking::request::Request,reqwest::error::Error>>
  invoke void @"_ZN4core3ptr108drop_in_place$LT$core..result..Result$LT$reqwest..blocking..request..Request$C$reqwest..error..Error$GT$$GT$17ha128715ca0872e06E"(ptr align 8 %req) #6
          to label %bb9 unwind label %terminate

terminate:                                        ; preds = %bb8, %bb6
  %13 = landingpad { ptr, i32 }
          filter [0 x ptr] zeroinitializer
  %14 = extractvalue { ptr, i32 } %13, 0
  %15 = extractvalue { ptr, i32 } %13, 1
; call core::panicking::panic_in_cleanup
  call void @_ZN4core9panicking16panic_in_cleanup17hb960b8c5dea287d4E() #7
  unreachable

bb5:                                              ; preds = %bb8, %bb9
  %16 = load ptr, ptr %0, align 8
  %17 = getelementptr inbounds i8, ptr %0, i64 8
  %18 = load i32, ptr %17, align 8
  %19 = insertvalue { ptr, i32 } poison, ptr %16, 0
  %20 = insertvalue { ptr, i32 } %19, i32 %18, 1
  resume { ptr, i32 } %20

bb8:                                              ; preds = %bb9
; invoke core::ptr::drop_in_place<http::method::Method>
  invoke void @"_ZN4core3ptr41drop_in_place$LT$http..method..Method$GT$17hc2cb167d8c5499b3E"(ptr align 8 %method) #6
          to label %bb5 unwind label %terminate
}

; reqwest::blocking::client::Client::request::{{closure}}
; Function Attrs: inlinehint uwtable
define void @"_ZN7reqwest8blocking6client6Client7request28_$u7b$$u7b$closure$u7d$$u7d$17hc2a440fd2e38b4cdE"(ptr sret([304 x i8]) align 8 %_0, ptr align 8 %_1, ptr align 8 %url) unnamed_addr #0 {
start:
  %_3 = alloca [24 x i8], align 8
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_3, ptr align 8 %_1, i64 24, i1 false)
; call reqwest::blocking::request::Request::new
  call void @_ZN7reqwest8blocking7request7Request3new17h20064da4f29284f5E(ptr sret([304 x i8]) align 8 %_0, ptr align 8 %_3, ptr align 8 %url)
  ret void
}

; reqwest::blocking::request::Request::new
; Function Attrs: inlinehint uwtable
define internal void @_ZN7reqwest8blocking7request7Request3new17h20064da4f29284f5E(ptr sret([304 x i8]) align 8 %_0, ptr align 8 %method, ptr align 8 %url) unnamed_addr #0 personality ptr @rust_eh_personality {
start:
  %0 = alloca [16 x i8], align 8
  %_4 = alloca [264 x i8], align 8
  %_3 = alloca [40 x i8], align 8
  store i64 2, ptr %_3, align 8
; invoke reqwest::async_impl::request::Request::new
  invoke void @_ZN7reqwest10async_impl7request7Request3new17hba466ca910ece236E(ptr sret([264 x i8]) align 8 %_4, ptr align 8 %method, ptr align 8 %url)
          to label %bb1 unwind label %cleanup

bb2:                                              ; preds = %cleanup
; invoke core::ptr::drop_in_place<core::option::Option<reqwest::blocking::body::Body>>
  invoke void @"_ZN4core3ptr78drop_in_place$LT$core..option..Option$LT$reqwest..blocking..body..Body$GT$$GT$17hfa62b521bf2b3feaE"(ptr align 8 %_3) #6
          to label %bb3 unwind label %terminate

cleanup:                                          ; preds = %start
  %1 = landingpad { ptr, i32 }
          cleanup
  %2 = extractvalue { ptr, i32 } %1, 0
  %3 = extractvalue { ptr, i32 } %1, 1
  store ptr %2, ptr %0, align 8
  %4 = getelementptr inbounds i8, ptr %0, i64 8
  store i32 %3, ptr %4, align 8
  br label %bb2

bb1:                                              ; preds = %start
  %5 = getelementptr inbounds i8, ptr %_0, i64 264
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %5, ptr align 8 %_3, i64 40, i1 false)
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_0, ptr align 8 %_4, i64 264, i1 false)
  ret void

terminate:                                        ; preds = %bb2
  %6 = landingpad { ptr, i32 }
          filter [0 x ptr] zeroinitializer
  %7 = extractvalue { ptr, i32 } %6, 0
  %8 = extractvalue { ptr, i32 } %6, 1
; call core::panicking::panic_in_cleanup
  call void @_ZN4core9panicking16panic_in_cleanup17hb960b8c5dea287d4E() #7
  unreachable

bb3:                                              ; preds = %bb2
  %9 = load ptr, ptr %0, align 8
  %10 = getelementptr inbounds i8, ptr %0, i64 8
  %11 = load i32, ptr %10, align 8
  %12 = insertvalue { ptr, i32 } poison, ptr %9, 0
  %13 = insertvalue { ptr, i32 } %12, i32 %11, 1
  resume { ptr, i32 } %13
}

; raw_http_reqwest::do_send
; Function Attrs: uwtable
define void @_ZN16raw_http_reqwest7do_send17hc0585c5cde5eb6c8E(ptr sret([32 x i8]) align 8 %_0) unnamed_addr #1 {
start:
  %0 = getelementptr inbounds i8, ptr %_0, i64 24
  store i8 0, ptr %0, align 8
  ret void
}

; raw_http_reqwest::do_send::{{closure}}
; Function Attrs: inlinehint uwtable
define zeroext i1 @"_ZN16raw_http_reqwest7do_send28_$u7b$$u7b$closure$u7d$$u7d$17hf4b7a3a1ad4fc27fE"(ptr align 8 %0, ptr align 8 %_2) unnamed_addr #0 personality ptr @rust_eh_personality {
start:
  %1 = alloca [16 x i8], align 8
  %_task_context = alloca [8 x i8], align 8
  %result = alloca [136 x i8], align 8
  %_8 = alloca [136 x i8], align 8
  %_6 = alloca [272 x i8], align 8
  %_3 = alloca [136 x i8], align 8
  %_0 = alloca [1 x i8], align 1
  %_1 = alloca [8 x i8], align 8
  store ptr %0, ptr %_1, align 8
  %_16 = load ptr, ptr %_1, align 8
  %2 = getelementptr inbounds i8, ptr %_16, i64 24
  %3 = load i8, ptr %2, align 8
  %_15 = zext i8 %3 to i32
  switch i32 %_15, label %bb9 [
    i32 0, label %bb1
    i32 1, label %bb20.preheader
    i32 2, label %bb19.preheader
    i32 3, label %bb18
  ]

bb19.preheader:                                   ; preds = %start
  br label %bb19

bb20.preheader:                                   ; preds = %start
  br label %bb20

bb9:                                              ; preds = %start
  unreachable

bb1:                                              ; preds = %start
  store ptr %_2, ptr %_task_context, align 8
  %_17 = load ptr, ptr %_1, align 8
; invoke reqwest::async_impl::client::Client::new
  %4 = invoke ptr @_ZN7reqwest10async_impl6client6Client3new17h5a978e80974a930bE()
          to label %bb2 unwind label %cleanup

bb20:                                             ; preds = %bb20.preheader, %bb20
  br i1 false, label %bb20, label %panic

bb19:                                             ; preds = %bb19.preheader, %bb19
  br i1 false, label %bb19, label %panic2

bb18:                                             ; preds = %start
  store ptr %_2, ptr %_task_context, align 8
  br label %bb6

bb17:                                             ; preds = %bb16, %cleanup
  %_27 = load ptr, ptr %_1, align 8
  %5 = getelementptr inbounds i8, ptr %_27, i64 24
  store i8 2, ptr %5, align 8
  %6 = load ptr, ptr %1, align 8
  %7 = getelementptr inbounds i8, ptr %1, i64 8
  %8 = load i32, ptr %7, align 8
  %9 = insertvalue { ptr, i32 } poison, ptr %6, 0
  %10 = insertvalue { ptr, i32 } %9, i32 %8, 1
  resume { ptr, i32 } %10

cleanup:                                          ; preds = %bb13, %bb1
  %11 = landingpad { ptr, i32 }
          cleanup
  %12 = extractvalue { ptr, i32 } %11, 0
  %13 = extractvalue { ptr, i32 } %11, 1
  store ptr %12, ptr %1, align 8
  %14 = getelementptr inbounds i8, ptr %1, i64 8
  store i32 %13, ptr %14, align 8
  br label %bb17

bb2:                                              ; preds = %bb1
  store ptr %4, ptr %_17, align 8
  %_18 = load ptr, ptr %_1, align 8
; invoke reqwest::async_impl::client::Client::get
  invoke void @_ZN7reqwest10async_impl6client6Client3get17hb005ac5db594dc27E(ptr sret([272 x i8]) align 8 %_6, ptr align 8 %_18, ptr align 1 @alloc_6ad81882bf157ce64a1f79ee864cdd93, i64 18)
          to label %bb3 unwind label %cleanup1

bb16:                                             ; preds = %bb15, %cleanup1
  %_26 = load ptr, ptr %_1, align 8
; invoke core::ptr::drop_in_place<reqwest::async_impl::client::Client>
  invoke void @"_ZN4core3ptr56drop_in_place$LT$reqwest..async_impl..client..Client$GT$17he5f1fedd540d99e6E"(ptr align 8 %_26) #6
          to label %bb17 unwind label %terminate

cleanup1:                                         ; preds = %bb12, %bb11, %bb4, %bb3, %bb2
  %15 = landingpad { ptr, i32 }
          cleanup
  %16 = extractvalue { ptr, i32 } %15, 0
  %17 = extractvalue { ptr, i32 } %15, 1
  store ptr %16, ptr %1, align 8
  %18 = getelementptr inbounds i8, ptr %1, i64 8
  store i32 %17, ptr %18, align 8
  br label %bb16

bb3:                                              ; preds = %bb2
; invoke reqwest::async_impl::request::RequestBuilder::send
  %19 = invoke { i64, ptr } @_ZN7reqwest10async_impl7request14RequestBuilder4send17hb7fc888fd554732dE(ptr align 8 %_6)
          to label %bb4 unwind label %cleanup1

bb4:                                              ; preds = %bb3
  %_5.0 = extractvalue { i64, ptr } %19, 0
  %_5.1 = extractvalue { i64, ptr } %19, 1
; invoke <F as core::future::into_future::IntoFuture>::into_future
  %20 = invoke { i64, ptr } @"_ZN59_$LT$F$u20$as$u20$core..future..into_future..IntoFuture$GT$11into_future17h32613fa1e2907a15E"(i64 %_5.0, ptr %_5.1)
          to label %bb5 unwind label %cleanup1

bb5:                                              ; preds = %bb4
  %_4.0 = extractvalue { i64, ptr } %20, 0
  %_4.1 = extractvalue { i64, ptr } %20, 1
  %_19 = load ptr, ptr %_1, align 8
  %21 = getelementptr inbounds i8, ptr %_19, i64 8
  store i64 %_4.0, ptr %21, align 8
  %22 = getelementptr inbounds i8, ptr %21, i64 8
  store ptr %_4.1, ptr %22, align 8
  br label %bb6

bb6:                                              ; preds = %bb18, %bb5
  %_20 = load ptr, ptr %_1, align 8
  %_10 = getelementptr inbounds i8, ptr %_20, i64 8
  br label %bb7

panic:                                            ; preds = %bb20
; call core::panicking::panic_const::panic_const_async_fn_resumed
  call void @_ZN4core9panicking11panic_const28panic_const_async_fn_resumed17hc64df446eef3dbfcE(ptr align 8 @alloc_c212be42f4214727c4ffd84fb86993b8) #8
  unreachable

panic2:                                           ; preds = %bb19
; call core::panicking::panic_const::panic_const_async_fn_resumed_panic
  call void @_ZN4core9panicking11panic_const34panic_const_async_fn_resumed_panic17hbbd8ac004b7fd30aE(ptr align 8 @alloc_c212be42f4214727c4ffd84fb86993b8) #8
  unreachable

bb15:                                             ; preds = %cleanup3
  %_25 = load ptr, ptr %_1, align 8
  %23 = getelementptr inbounds i8, ptr %_25, i64 8
; invoke core::ptr::drop_in_place<reqwest::async_impl::client::Pending>
  invoke void @"_ZN4core3ptr57drop_in_place$LT$reqwest..async_impl..client..Pending$GT$17ha0c4d20cc150ed16E"(ptr align 8 %23) #6
          to label %bb16 unwind label %terminate

cleanup3:                                         ; preds = %bb7
  %24 = landingpad { ptr, i32 }
          cleanup
  %25 = extractvalue { ptr, i32 } %24, 0
  %26 = extractvalue { ptr, i32 } %24, 1
  store ptr %25, ptr %1, align 8
  %27 = getelementptr inbounds i8, ptr %1, i64 8
  store i32 %26, ptr %27, align 8
  br label %bb15

bb7:                                              ; preds = %bb6
  %_11 = load ptr, ptr %_task_context, align 8
; invoke <reqwest::async_impl::client::Pending as core::future::future::Future>::poll
  invoke void @"_ZN85_$LT$reqwest..async_impl..client..Pending$u20$as$u20$core..future..future..Future$GT$4poll17h85554b7e73552205E"(ptr sret([136 x i8]) align 8 %_8, ptr align 8 %_10, ptr align 8 %_11)
          to label %bb8 unwind label %cleanup3

bb8:                                              ; preds = %bb7
  %28 = load i64, ptr %_8, align 8
  %29 = icmp eq i64 %28, 4
  %_12 = select i1 %29, i64 1, i64 0
  %30 = icmp eq i64 %_12, 0
  br i1 %30, label %bb11, label %bb10

bb11:                                             ; preds = %bb8
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %result, ptr align 8 %_8, i64 136, i1 false)
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_3, ptr align 8 %result, i64 136, i1 false)
  %_22 = load ptr, ptr %_1, align 8
  %31 = getelementptr inbounds i8, ptr %_22, i64 8
; invoke core::ptr::drop_in_place<reqwest::async_impl::client::Pending>
  invoke void @"_ZN4core3ptr57drop_in_place$LT$reqwest..async_impl..client..Pending$GT$17ha0c4d20cc150ed16E"(ptr align 8 %31)
          to label %bb12 unwind label %cleanup1

bb10:                                             ; preds = %bb8
  store i8 1, ptr %_0, align 1
  %_21 = load ptr, ptr %_1, align 8
  %32 = getelementptr inbounds i8, ptr %_21, i64 24
  store i8 3, ptr %32, align 8
  %33 = load i8, ptr %_0, align 1
  %34 = trunc i8 %33 to i1
  ret i1 %34

bb12:                                             ; preds = %bb11
; invoke core::ptr::drop_in_place<core::result::Result<reqwest::async_impl::response::Response,reqwest::error::Error>>
  invoke void @"_ZN4core3ptr112drop_in_place$LT$core..result..Result$LT$reqwest..async_impl..response..Response$C$reqwest..error..Error$GT$$GT$17had38b4bd3c1ed9d1E"(ptr align 8 %_3)
          to label %bb13 unwind label %cleanup1

bb13:                                             ; preds = %bb12
  %_23 = load ptr, ptr %_1, align 8
; invoke core::ptr::drop_in_place<reqwest::async_impl::client::Client>
  invoke void @"_ZN4core3ptr56drop_in_place$LT$reqwest..async_impl..client..Client$GT$17he5f1fedd540d99e6E"(ptr align 8 %_23)
          to label %bb14 unwind label %cleanup

bb14:                                             ; preds = %bb13
  store i8 0, ptr %_0, align 1
  %_24 = load ptr, ptr %_1, align 8
  %35 = getelementptr inbounds i8, ptr %_24, i64 24
  store i8 1, ptr %35, align 8
  %36 = load i8, ptr %_0, align 1
  %37 = trunc i8 %36 to i1
  ret i1 %37

terminate:                                        ; preds = %bb16, %bb15
  %38 = landingpad { ptr, i32 }
          filter [0 x ptr] zeroinitializer
  %39 = extractvalue { ptr, i32 } %38, 0
  %40 = extractvalue { ptr, i32 } %38, 1
; call core::panicking::panic_in_cleanup
  call void @_ZN4core9panicking16panic_in_cleanup17hb960b8c5dea287d4E() #7
  unreachable
}

; raw_http_reqwest::do_blocking_send
; Function Attrs: uwtable
define void @_ZN16raw_http_reqwest16do_blocking_send17ha4fcff335645866dE() unnamed_addr #1 personality ptr @rust_eh_personality {
start:
  %0 = alloca [16 x i8], align 8
  %_3 = alloca [328 x i8], align 8
  %_2 = alloca [176 x i8], align 8
  %client = alloca [24 x i8], align 8
; call reqwest::blocking::client::Client::new
  call void @_ZN7reqwest8blocking6client6Client3new17h504e7058f0adcc69E(ptr sret([24 x i8]) align 8 %client)
; invoke reqwest::blocking::client::Client::get
  invoke void @_ZN7reqwest8blocking6client6Client3get17h1d67d1645865cd36E(ptr sret([328 x i8]) align 8 %_3, ptr align 8 %client, ptr align 1 @alloc_6ad81882bf157ce64a1f79ee864cdd93, i64 18)
          to label %bb2 unwind label %cleanup

bb6:                                              ; preds = %cleanup
; invoke core::ptr::drop_in_place<reqwest::blocking::client::Client>
  invoke void @"_ZN4core3ptr54drop_in_place$LT$reqwest..blocking..client..Client$GT$17h01c1a5fac2d12401E"(ptr align 8 %client) #6
          to label %bb7 unwind label %terminate

cleanup:                                          ; preds = %bb3, %bb2, %start
  %1 = landingpad { ptr, i32 }
          cleanup
  %2 = extractvalue { ptr, i32 } %1, 0
  %3 = extractvalue { ptr, i32 } %1, 1
  store ptr %2, ptr %0, align 8
  %4 = getelementptr inbounds i8, ptr %0, i64 8
  store i32 %3, ptr %4, align 8
  br label %bb6

bb2:                                              ; preds = %start
; invoke reqwest::blocking::request::RequestBuilder::send
  invoke void @_ZN7reqwest8blocking7request14RequestBuilder4send17h2656b611f8aef53fE(ptr sret([176 x i8]) align 8 %_2, ptr align 8 %_3)
          to label %bb3 unwind label %cleanup

bb3:                                              ; preds = %bb2
; invoke core::ptr::drop_in_place<core::result::Result<reqwest::blocking::response::Response,reqwest::error::Error>>
  invoke void @"_ZN4core3ptr110drop_in_place$LT$core..result..Result$LT$reqwest..blocking..response..Response$C$reqwest..error..Error$GT$$GT$17hb5bbef2a0caa3090E"(ptr align 8 %_2)
          to label %bb4 unwind label %cleanup

bb4:                                              ; preds = %bb3
; call core::ptr::drop_in_place<reqwest::blocking::client::Client>
  call void @"_ZN4core3ptr54drop_in_place$LT$reqwest..blocking..client..Client$GT$17h01c1a5fac2d12401E"(ptr align 8 %client)
  ret void

terminate:                                        ; preds = %bb6
  %5 = landingpad { ptr, i32 }
          filter [0 x ptr] zeroinitializer
  %6 = extractvalue { ptr, i32 } %5, 0
  %7 = extractvalue { ptr, i32 } %5, 1
; call core::panicking::panic_in_cleanup
  call void @_ZN4core9panicking16panic_in_cleanup17hb960b8c5dea287d4E() #7
  unreachable

bb7:                                              ; preds = %bb6
  %8 = load ptr, ptr %0, align 8
  %9 = getelementptr inbounds i8, ptr %0, i64 8
  %10 = load i32, ptr %9, align 8
  %11 = insertvalue { ptr, i32 } poison, ptr %8, 0
  %12 = insertvalue { ptr, i32 } %11, i32 %10, 1
  resume { ptr, i32 } %12
}

; raw_http_reqwest::drive_do_send_once
; Function Attrs: uwtable
define void @_ZN16raw_http_reqwest18drive_do_send_once17hde5f3da7d1cc7496E() unnamed_addr #1 personality ptr @rust_eh_personality {
start:
  %0 = alloca [16 x i8], align 8
  %_10 = alloca [8 x i8], align 8
  %cx = alloca [32 x i8], align 8
  %_3 = alloca [32 x i8], align 8
  %fut = alloca [8 x i8], align 8
; call raw_http_reqwest::do_send
  call void @_ZN16raw_http_reqwest7do_send17hc0585c5cde5eb6c8E(ptr sret([32 x i8]) align 8 %_3)
  store ptr %_3, ptr %_10, align 8
  %1 = load ptr, ptr %_10, align 8
  store ptr %1, ptr %fut, align 8
; invoke core::task::wake::Waker::noop
  %waker = invoke align 8 ptr @_ZN4core4task4wake5Waker4noop17h3a2266c439c47f60E()
          to label %bb2 unwind label %cleanup

bb7:                                              ; preds = %cleanup
; invoke core::ptr::drop_in_place<raw_http_reqwest::do_send::{{closure}}>
  invoke void @"_ZN4core3ptr75drop_in_place$LT$raw_http_reqwest..do_send..$u7b$$u7b$closure$u7d$$u7d$$GT$17hfb9f22acc9bc8cb4E"(ptr align 8 %_3) #6
          to label %bb8 unwind label %terminate

cleanup:                                          ; preds = %bb3, %bb4, %bb2, %start
  %2 = landingpad { ptr, i32 }
          cleanup
  %3 = extractvalue { ptr, i32 } %2, 0
  %4 = extractvalue { ptr, i32 } %2, 1
  store ptr %3, ptr %0, align 8
  %5 = getelementptr inbounds i8, ptr %0, i64 8
  store i32 %4, ptr %5, align 8
  br label %bb7

bb2:                                              ; preds = %start
; invoke core::task::wake::Context::from_waker
  invoke void @_ZN4core4task4wake7Context10from_waker17hb12f415282b2e7d6E(ptr sret([32 x i8]) align 8 %cx, ptr align 8 %waker)
          to label %bb3 unwind label %cleanup

bb3:                                              ; preds = %bb2
; invoke <&mut T as core::ops::deref::DerefMut>::deref_mut
  %pointer.i1 = invoke align 8 ptr @"_ZN60_$LT$$RF$mut$u20$T$u20$as$u20$core..ops..deref..DerefMut$GT$9deref_mut17h0bd9729e2744b2cdE"(ptr align 8 %fut)
          to label %"_ZN4core3pin14Pin$LT$Ptr$GT$6as_mut17h8b5c42396640c70bE.exit" unwind label %cleanup

"_ZN4core3pin14Pin$LT$Ptr$GT$6as_mut17h8b5c42396640c70bE.exit": ; preds = %bb3
  br label %bb4

bb4:                                              ; preds = %"_ZN4core3pin14Pin$LT$Ptr$GT$6as_mut17h8b5c42396640c70bE.exit"
; invoke raw_http_reqwest::do_send::{{closure}}
  %_6 = invoke zeroext i1 @"_ZN16raw_http_reqwest7do_send28_$u7b$$u7b$closure$u7d$$u7d$17hf4b7a3a1ad4fc27fE"(ptr align 8 %pointer.i1, ptr align 8 %cx)
          to label %bb5 unwind label %cleanup

bb5:                                              ; preds = %bb4
; call core::ptr::drop_in_place<raw_http_reqwest::do_send::{{closure}}>
  call void @"_ZN4core3ptr75drop_in_place$LT$raw_http_reqwest..do_send..$u7b$$u7b$closure$u7d$$u7d$$GT$17hfb9f22acc9bc8cb4E"(ptr align 8 %_3)
  ret void

terminate:                                        ; preds = %bb7
  %6 = landingpad { ptr, i32 }
          filter [0 x ptr] zeroinitializer
  %7 = extractvalue { ptr, i32 } %6, 0
  %8 = extractvalue { ptr, i32 } %6, 1
; call core::panicking::panic_in_cleanup
  call void @_ZN4core9panicking16panic_in_cleanup17hb960b8c5dea287d4E() #7
  unreachable

bb8:                                              ; preds = %bb7
  %9 = load ptr, ptr %0, align 8
  %10 = getelementptr inbounds i8, ptr %0, i64 8
  %11 = load i32, ptr %10, align 8
  %12 = insertvalue { ptr, i32 } poison, ptr %9, 0
  %13 = insertvalue { ptr, i32 } %12, i32 %11, 1
  resume { ptr, i32 } %13
}

; Function Attrs: nounwind uwtable
declare i32 @rust_eh_personality(i32, i32, i64, ptr, ptr) unnamed_addr #2

; core::ptr::drop_in_place<http::method::Method>
; Function Attrs: uwtable
declare void @"_ZN4core3ptr41drop_in_place$LT$http..method..Method$GT$17hc2cb167d8c5499b3E"(ptr align 8) unnamed_addr #1

; core::ptr::drop_in_place<reqwest::error::Error>
; Function Attrs: uwtable
declare void @"_ZN4core3ptr42drop_in_place$LT$reqwest..error..Error$GT$17h27d879affa0191e1E"(ptr align 8) unnamed_addr #1

; core::ptr::drop_in_place<reqwest::async_impl::response::Response>
; Function Attrs: uwtable
declare void @"_ZN4core3ptr60drop_in_place$LT$reqwest..async_impl..response..Response$GT$17h9433d2fbf2bf5649E"(ptr align 8) unnamed_addr #1

; core::ptr::drop_in_place<core::option::Option<core::pin::Pin<alloc::boxed::Box<dyn futures_io::if_std::AsyncRead+core::marker::Send+core::marker::Sync>>>>
; Function Attrs: uwtable
declare void @"_ZN4core3ptr179drop_in_place$LT$core..option..Option$LT$core..pin..Pin$LT$alloc..boxed..Box$LT$dyn$u20$futures_io..if_std..AsyncRead$u2b$core..marker..Send$u2b$core..marker..Sync$GT$$GT$$GT$$GT$17h41ac32546485c774E"(ptr align 8) unnamed_addr #1

; core::ptr::drop_in_place<reqwest::blocking::client::KeepCoreThreadAlive>
; Function Attrs: uwtable
declare void @"_ZN4core3ptr67drop_in_place$LT$reqwest..blocking..client..KeepCoreThreadAlive$GT$17he03b48440cc42b6cE"(ptr align 8) unnamed_addr #1

; core::panicking::panic_in_cleanup
; Function Attrs: cold minsize noinline noreturn nounwind optsize uwtable
declare void @_ZN4core9panicking16panic_in_cleanup17hb960b8c5dea287d4E() unnamed_addr #3

; core::ptr::drop_in_place<reqwest::async_impl::client::Pending>
; Function Attrs: uwtable
declare void @"_ZN4core3ptr57drop_in_place$LT$reqwest..async_impl..client..Pending$GT$17ha0c4d20cc150ed16E"(ptr align 8) unnamed_addr #1

; core::ptr::drop_in_place<reqwest::async_impl::client::Client>
; Function Attrs: uwtable
declare void @"_ZN4core3ptr56drop_in_place$LT$reqwest..async_impl..client..Client$GT$17he5f1fedd540d99e6E"(ptr align 8) unnamed_addr #1

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: readwrite)
declare void @llvm.memcpy.p0.p0.i64(ptr noalias nocapture writeonly, ptr noalias nocapture readonly, i64, i1 immarg) #4

; <http::header::map::HeaderMap<T> as core::default::Default>::default
; Function Attrs: uwtable
declare void @"_ZN80_$LT$http..header..map..HeaderMap$LT$T$GT$$u20$as$u20$core..default..Default$GT$7default17h5832afa0117982a9E"(ptr sret([96 x i8]) align 8) unnamed_addr #1

; <alloc::sync::Arc<T,A> as core::clone::Clone>::clone
; Function Attrs: inlinehint uwtable
declare ptr @"_ZN68_$LT$alloc..sync..Arc$LT$T$C$A$GT$$u20$as$u20$core..clone..Clone$GT$5clone17h33ccda2c0e054e36E"(ptr align 8) unnamed_addr #0

; <alloc::sync::Arc<T,A> as core::clone::Clone>::clone
; Function Attrs: inlinehint uwtable
declare ptr @"_ZN68_$LT$alloc..sync..Arc$LT$T$C$A$GT$$u20$as$u20$core..clone..Clone$GT$5clone17hed23787606f596e0E"(ptr align 8) unnamed_addr #0

; <&str as reqwest::into_url::IntoUrlSealed>::into_url
; Function Attrs: uwtable
declare void @"_ZN60_$LT$$RF$str$u20$as$u20$reqwest..into_url..IntoUrlSealed$GT$8into_url17he89b26eee4e66eeaE"(ptr sret([88 x i8]) align 8, ptr align 1, i64) unnamed_addr #1

; reqwest::async_impl::request::RequestBuilder::new
; Function Attrs: uwtable
declare void @_ZN7reqwest10async_impl7request14RequestBuilder3new17h0e12ddd9f5f32108E(ptr sret([272 x i8]) align 8, ptr, ptr align 8) unnamed_addr #1

; core::ptr::drop_in_place<core::result::Result<reqwest::async_impl::request::Request,reqwest::error::Error>>
; Function Attrs: uwtable
declare void @"_ZN4core3ptr110drop_in_place$LT$core..result..Result$LT$reqwest..async_impl..request..Request$C$reqwest..error..Error$GT$$GT$17he27e495364365f84E"(ptr align 8) unnamed_addr #1

; core::ptr::drop_in_place<core::option::Option<reqwest::async_impl::body::Body>>
; Function Attrs: uwtable
declare void @"_ZN4core3ptr80drop_in_place$LT$core..option..Option$LT$reqwest..async_impl..body..Body$GT$$GT$17h47dd78234e6ecd91E"(ptr align 8) unnamed_addr #1

; core::ptr::drop_in_place<http::header::map::HeaderMap>
; Function Attrs: uwtable
declare void @"_ZN4core3ptr49drop_in_place$LT$http..header..map..HeaderMap$GT$17h97924f40e575a3f7E"(ptr align 8) unnamed_addr #1

; core::ptr::drop_in_place<url::Url>
; Function Attrs: uwtable
declare void @"_ZN4core3ptr29drop_in_place$LT$url..Url$GT$17hc00100ec9bd43773E"(ptr align 8) unnamed_addr #1

; reqwest::blocking::request::RequestBuilder::new
; Function Attrs: uwtable
declare void @_ZN7reqwest8blocking7request14RequestBuilder3new17hd92757e2ea46310fE(ptr sret([328 x i8]) align 8, ptr align 8, ptr align 8) unnamed_addr #1

; core::ptr::drop_in_place<core::result::Result<reqwest::blocking::request::Request,reqwest::error::Error>>
; Function Attrs: uwtable
declare void @"_ZN4core3ptr108drop_in_place$LT$core..result..Result$LT$reqwest..blocking..request..Request$C$reqwest..error..Error$GT$$GT$17ha128715ca0872e06E"(ptr align 8) unnamed_addr #1

; core::ptr::drop_in_place<core::option::Option<reqwest::blocking::body::Body>>
; Function Attrs: uwtable
declare void @"_ZN4core3ptr78drop_in_place$LT$core..option..Option$LT$reqwest..blocking..body..Body$GT$$GT$17hfa62b521bf2b3feaE"(ptr align 8) unnamed_addr #1

; reqwest::async_impl::client::Client::new
; Function Attrs: uwtable
declare ptr @_ZN7reqwest10async_impl6client6Client3new17h5a978e80974a930bE() unnamed_addr #1

; reqwest::async_impl::request::RequestBuilder::send
; Function Attrs: uwtable
declare { i64, ptr } @_ZN7reqwest10async_impl7request14RequestBuilder4send17hb7fc888fd554732dE(ptr align 8) unnamed_addr #1

; core::panicking::panic_const::panic_const_async_fn_resumed
; Function Attrs: cold noinline noreturn uwtable
declare void @_ZN4core9panicking11panic_const28panic_const_async_fn_resumed17hc64df446eef3dbfcE(ptr align 8) unnamed_addr #5

; core::panicking::panic_const::panic_const_async_fn_resumed_panic
; Function Attrs: cold noinline noreturn uwtable
declare void @_ZN4core9panicking11panic_const34panic_const_async_fn_resumed_panic17hbbd8ac004b7fd30aE(ptr align 8) unnamed_addr #5

; <reqwest::async_impl::client::Pending as core::future::future::Future>::poll
; Function Attrs: uwtable
declare void @"_ZN85_$LT$reqwest..async_impl..client..Pending$u20$as$u20$core..future..future..Future$GT$4poll17h85554b7e73552205E"(ptr sret([136 x i8]) align 8, ptr align 8, ptr align 8) unnamed_addr #1

; core::ptr::drop_in_place<core::result::Result<reqwest::async_impl::response::Response,reqwest::error::Error>>
; Function Attrs: uwtable
declare void @"_ZN4core3ptr112drop_in_place$LT$core..result..Result$LT$reqwest..async_impl..response..Response$C$reqwest..error..Error$GT$$GT$17had38b4bd3c1ed9d1E"(ptr align 8) unnamed_addr #1

; reqwest::blocking::client::Client::new
; Function Attrs: uwtable
declare void @_ZN7reqwest8blocking6client6Client3new17h504e7058f0adcc69E(ptr sret([24 x i8]) align 8) unnamed_addr #1

; reqwest::blocking::request::RequestBuilder::send
; Function Attrs: uwtable
declare void @_ZN7reqwest8blocking7request14RequestBuilder4send17h2656b611f8aef53fE(ptr sret([176 x i8]) align 8, ptr align 8) unnamed_addr #1

; core::ptr::drop_in_place<reqwest::blocking::client::Client>
; Function Attrs: uwtable
declare void @"_ZN4core3ptr54drop_in_place$LT$reqwest..blocking..client..Client$GT$17h01c1a5fac2d12401E"(ptr align 8) unnamed_addr #1

attributes #0 = { inlinehint uwtable "frame-pointer"="non-leaf" "probe-stack"="inline-asm" "target-cpu"="apple-m1" }
attributes #1 = { uwtable "frame-pointer"="non-leaf" "probe-stack"="inline-asm" "target-cpu"="apple-m1" }
attributes #2 = { nounwind uwtable "frame-pointer"="non-leaf" "probe-stack"="inline-asm" "target-cpu"="apple-m1" }
attributes #3 = { cold minsize noinline noreturn nounwind optsize uwtable "frame-pointer"="non-leaf" "probe-stack"="inline-asm" "target-cpu"="apple-m1" }
attributes #4 = { nocallback nofree nounwind willreturn memory(argmem: readwrite) }
attributes #5 = { cold noinline noreturn uwtable "frame-pointer"="non-leaf" "probe-stack"="inline-asm" "target-cpu"="apple-m1" }
attributes #6 = { cold }
attributes #7 = { cold noreturn nounwind }
attributes #8 = { noreturn }

!llvm.module.flags = !{!0}
!llvm.ident = !{!1}

!0 = !{i32 8, !"PIC Level", i32 2}
!1 = !{!"rustc version 1.86.0 (05f9846f8 2025-03-31)"}
