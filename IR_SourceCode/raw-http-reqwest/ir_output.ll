; ModuleID = '5mtg6167k2ayyeq4p8adfo4hf'
source_filename = "5mtg6167k2ayyeq4p8adfo4hf"
target datalayout = "e-m:w-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-windows-msvc"

@alloc_a9789c9151c50f11596d118305db5499 = private unnamed_addr constant <{ ptr, ptr, ptr, ptr }> <{ ptr @_ZN4core3ops8function6FnOnce9call_once17h2fe8b8342481cf33E, ptr @_ZN4core3ops8function6FnOnce9call_once17h699b718e56567613E, ptr @_ZN4core3ops8function6FnOnce9call_once17h7dd3d85c53a285baE, ptr @_ZN4core3ops8function6FnOnce9call_once17h17ba23fa8d8d9aa0E }>, align 8
@alloc_034d8ce7c7446840ac80139172d67d00 = private unnamed_addr constant <{ ptr, [8 x i8] }> <{ ptr @alloc_a9789c9151c50f11596d118305db5499, [8 x i8] zeroinitializer }>, align 8
@0 = private unnamed_addr constant <{ [8 x i8], [8 x i8] }> <{ [8 x i8] zeroinitializer, [8 x i8] undef }>, align 8
@1 = private unnamed_addr constant <{ [1 x i8], [23 x i8] }> <{ [1 x i8] c"\01", [23 x i8] undef }>, align 8
@alloc_6ad81882bf157ce64a1f79ee864cdd93 = private unnamed_addr constant <{ [18 x i8] }> <{ [18 x i8] c"http://example.com" }>, align 1
@alloc_4771401c1b62ff9602a855ecda415c51 = private unnamed_addr constant <{ [10 x i8] }> <{ [10 x i8] c"src\\lib.rs" }>, align 1
@alloc_9c46cdc72b2e47ad975360fa9a270d09 = private unnamed_addr constant <{ ptr, [16 x i8] }> <{ ptr @alloc_4771401c1b62ff9602a855ecda415c51, [16 x i8] c"\0A\00\00\00\00\00\00\00\18\00\00\00\18\00\00\00" }>, align 8

; core::ops::function::FnOnce::call_once
; Function Attrs: inlinehint uwtable
define internal void @_ZN4core3ops8function6FnOnce9call_once17h17ba23fa8d8d9aa0E(ptr %0) unnamed_addr #0 personality ptr @__CxxFrameHandler3 {
start:
  %_2 = alloca [8 x i8], align 8
  %_1 = alloca [0 x i8], align 1
  store ptr %0, ptr %_2, align 8
  %1 = load ptr, ptr %_2, align 8
; invoke core::task::wake::RawWaker::NOOP::VTABLE::{{closure}}
  invoke void @"_ZN4core4task4wake8RawWaker4NOOP6VTABLE28_$u7b$$u7b$closure$u7d$$u7d$17hb1bc70aea3680149E"(ptr align 1 %_1, ptr %1)
          to label %bb1 unwind label %funclet_bb3

bb3:                                              ; preds = %funclet_bb3
  cleanupret from %cleanuppad unwind to caller

funclet_bb3:                                      ; preds = %start
  %cleanuppad = cleanuppad within none []
  br label %bb3

bb1:                                              ; preds = %start
  ret void
}

; core::ops::function::FnOnce::call_once
; Function Attrs: inlinehint uwtable
define internal { ptr, ptr } @_ZN4core3ops8function6FnOnce9call_once17h2fe8b8342481cf33E(ptr %0) unnamed_addr #0 personality ptr @__CxxFrameHandler3 {
start:
  %_2 = alloca [8 x i8], align 8
  %_1 = alloca [0 x i8], align 1
  store ptr %0, ptr %_2, align 8
  %1 = load ptr, ptr %_2, align 8
; invoke core::task::wake::RawWaker::NOOP::VTABLE::{{closure}}
  %2 = invoke { ptr, ptr } @"_ZN4core4task4wake8RawWaker4NOOP6VTABLE28_$u7b$$u7b$closure$u7d$$u7d$17hd05ec6b3a6a72803E"(ptr align 1 %_1, ptr %1)
          to label %bb1 unwind label %funclet_bb3

bb3:                                              ; preds = %funclet_bb3
  cleanupret from %cleanuppad unwind to caller

funclet_bb3:                                      ; preds = %start
  %cleanuppad = cleanuppad within none []
  br label %bb3

bb1:                                              ; preds = %start
  %_0.0 = extractvalue { ptr, ptr } %2, 0
  %_0.1 = extractvalue { ptr, ptr } %2, 1
  %3 = insertvalue { ptr, ptr } poison, ptr %_0.0, 0
  %4 = insertvalue { ptr, ptr } %3, ptr %_0.1, 1
  ret { ptr, ptr } %4
}

; core::ops::function::FnOnce::call_once
; Function Attrs: inlinehint uwtable
define internal void @_ZN4core3ops8function6FnOnce9call_once17h699b718e56567613E(ptr %0) unnamed_addr #0 personality ptr @__CxxFrameHandler3 {
start:
  %_2 = alloca [8 x i8], align 8
  %_1 = alloca [0 x i8], align 1
  store ptr %0, ptr %_2, align 8
  %1 = load ptr, ptr %_2, align 8
; invoke core::task::wake::RawWaker::NOOP::VTABLE::{{closure}}
  invoke void @"_ZN4core4task4wake8RawWaker4NOOP6VTABLE28_$u7b$$u7b$closure$u7d$$u7d$17h4c2db514003e777aE"(ptr align 1 %_1, ptr %1)
          to label %bb1 unwind label %funclet_bb3

bb3:                                              ; preds = %funclet_bb3
  cleanupret from %cleanuppad unwind to caller

funclet_bb3:                                      ; preds = %start
  %cleanuppad = cleanuppad within none []
  br label %bb3

bb1:                                              ; preds = %start
  ret void
}

; core::ops::function::FnOnce::call_once
; Function Attrs: inlinehint uwtable
define internal void @_ZN4core3ops8function6FnOnce9call_once17h7dd3d85c53a285baE(ptr %0) unnamed_addr #0 personality ptr @__CxxFrameHandler3 {
start:
  %_2 = alloca [8 x i8], align 8
  %_1 = alloca [0 x i8], align 1
  store ptr %0, ptr %_2, align 8
  %1 = load ptr, ptr %_2, align 8
; invoke core::task::wake::RawWaker::NOOP::VTABLE::{{closure}}
  invoke void @"_ZN4core4task4wake8RawWaker4NOOP6VTABLE28_$u7b$$u7b$closure$u7d$$u7d$17h641525f75c0b5d0cE"(ptr align 1 %_1, ptr %1)
          to label %bb1 unwind label %funclet_bb3

bb3:                                              ; preds = %funclet_bb3
  cleanupret from %cleanuppad unwind to caller

funclet_bb3:                                      ; preds = %start
  %cleanuppad = cleanuppad within none []
  br label %bb3

bb1:                                              ; preds = %start
  ret void
}

; core::ptr::drop_in_place<reqwest::blocking::client::Client::request<&str>::{{closure}}>
; Function Attrs: uwtable
define void @"_ZN4core3ptr107drop_in_place$LT$reqwest..blocking..client..Client..request$LT$$RF$str$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$17h904306e8c1d44a7aE"(ptr align 8 %_1) unnamed_addr #1 {
start:
; call core::ptr::drop_in_place<http::method::Method>
  call void @"_ZN4core3ptr41drop_in_place$LT$http..method..Method$GT$17h2d651b10f05c5163E"(ptr align 8 %_1)
  ret void
}

; core::ptr::drop_in_place<reqwest::async_impl::client::Client::request<&str>::{{closure}}>
; Function Attrs: uwtable
define void @"_ZN4core3ptr109drop_in_place$LT$reqwest..async_impl..client..Client..request$LT$$RF$str$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$17hd7ba6dfd33a6e1f7E"(ptr align 8 %_1) unnamed_addr #1 {
start:
; call core::ptr::drop_in_place<http::method::Method>
  call void @"_ZN4core3ptr41drop_in_place$LT$http..method..Method$GT$17h2d651b10f05c5163E"(ptr align 8 %_1)
  ret void
}

; core::ptr::drop_in_place<core::result::Result<reqwest::blocking::response::Response,reqwest::error::Error>>
; Function Attrs: uwtable
define void @"_ZN4core3ptr110drop_in_place$LT$core..result..Result$LT$reqwest..blocking..response..Response$C$reqwest..error..Error$GT$$GT$17he89259276819211bE"(ptr align 8 %_1) unnamed_addr #1 {
start:
  %0 = load i64, ptr %_1, align 8
  %1 = icmp eq i64 %0, 3
  %_2 = select i1 %1, i64 1, i64 0
  %2 = icmp eq i64 %_2, 0
  br i1 %2, label %bb2, label %bb3

bb2:                                              ; preds = %start
; call core::ptr::drop_in_place<reqwest::blocking::response::Response>
  call void @"_ZN4core3ptr58drop_in_place$LT$reqwest..blocking..response..Response$GT$17hb5fb3c035c55fc74E"(ptr align 8 %_1)
  br label %bb1

bb3:                                              ; preds = %start
  %3 = getelementptr inbounds i8, ptr %_1, i64 8
; call core::ptr::drop_in_place<reqwest::error::Error>
  call void @"_ZN4core3ptr42drop_in_place$LT$reqwest..error..Error$GT$17ha8734def48176607E"(ptr align 8 %3)
  br label %bb1

bb1:                                              ; preds = %bb3, %bb2
  ret void
}

; core::ptr::drop_in_place<reqwest::blocking::response::Response>
; Function Attrs: uwtable
define void @"_ZN4core3ptr58drop_in_place$LT$reqwest..blocking..response..Response$GT$17hb5fb3c035c55fc74E"(ptr align 8 %_1) unnamed_addr #1 personality ptr @__CxxFrameHandler3 {
start:
; invoke core::ptr::drop_in_place<reqwest::async_impl::response::Response>
  invoke void @"_ZN4core3ptr60drop_in_place$LT$reqwest..async_impl..response..Response$GT$17h75c48e7e34ebe94aE"(ptr align 8 %_1)
          to label %bb6 unwind label %funclet_bb4

bb4:                                              ; preds = %funclet_bb4
  %0 = getelementptr inbounds i8, ptr %_1, i64 152
; call core::ptr::drop_in_place<core::option::Option<core::pin::Pin<alloc::boxed::Box<dyn futures_io::if_std::AsyncRead+core::marker::Sync+core::marker::Send>>>>
  call void @"_ZN4core3ptr179drop_in_place$LT$core..option..Option$LT$core..pin..Pin$LT$alloc..boxed..Box$LT$dyn$u20$futures_io..if_std..AsyncRead$u2b$core..marker..Sync$u2b$core..marker..Send$GT$$GT$$GT$$GT$17hab6f516f4e5d2633E"(ptr align 8 %0) #5 [ "funclet"(token %cleanuppad) ]
  cleanupret from %cleanuppad unwind label %funclet_bb3

funclet_bb4:                                      ; preds = %start
  %cleanuppad = cleanuppad within none []
  br label %bb4

bb6:                                              ; preds = %start
  %1 = getelementptr inbounds i8, ptr %_1, i64 152
; invoke core::ptr::drop_in_place<core::option::Option<core::pin::Pin<alloc::boxed::Box<dyn futures_io::if_std::AsyncRead+core::marker::Sync+core::marker::Send>>>>
  invoke void @"_ZN4core3ptr179drop_in_place$LT$core..option..Option$LT$core..pin..Pin$LT$alloc..boxed..Box$LT$dyn$u20$futures_io..if_std..AsyncRead$u2b$core..marker..Sync$u2b$core..marker..Send$GT$$GT$$GT$$GT$17hab6f516f4e5d2633E"(ptr align 8 %1)
          to label %bb5 unwind label %funclet_bb3

bb3:                                              ; preds = %funclet_bb3
  %2 = getelementptr inbounds i8, ptr %_1, i64 168
; call core::ptr::drop_in_place<reqwest::blocking::client::KeepCoreThreadAlive>
  call void @"_ZN4core3ptr67drop_in_place$LT$reqwest..blocking..client..KeepCoreThreadAlive$GT$17h22f341cced4ba138E"(ptr align 8 %2) #5 [ "funclet"(token %cleanuppad1) ]
  cleanupret from %cleanuppad1 unwind to caller

funclet_bb3:                                      ; preds = %bb4, %bb6
  %cleanuppad1 = cleanuppad within none []
  br label %bb3

bb5:                                              ; preds = %bb6
  %3 = getelementptr inbounds i8, ptr %_1, i64 168
; call core::ptr::drop_in_place<reqwest::blocking::client::KeepCoreThreadAlive>
  call void @"_ZN4core3ptr67drop_in_place$LT$reqwest..blocking..client..KeepCoreThreadAlive$GT$17h22f341cced4ba138E"(ptr align 8 %3)
  ret void
}

; core::ptr::drop_in_place<raw_http_reqwest::do_send::{{closure}}>
; Function Attrs: uwtable
define void @"_ZN4core3ptr75drop_in_place$LT$raw_http_reqwest..do_send..$u7b$$u7b$closure$u7d$$u7d$$GT$17h302c5163c1aa99dcE"(ptr align 8 %_1) unnamed_addr #1 personality ptr @__CxxFrameHandler3 {
start:
  %0 = getelementptr inbounds i8, ptr %_1, i64 24
  %1 = load i8, ptr %0, align 8
  %_30 = zext i8 %1 to i32
  switch i32 %_30, label %bb15 [
    i32 0, label %bb11
    i32 3, label %bb14
  ]

bb15:                                             ; preds = %start
  ret void

bb11:                                             ; preds = %start
  ret void

bb14:                                             ; preds = %start
  %2 = getelementptr inbounds i8, ptr %_1, i64 8
; invoke core::ptr::drop_in_place<reqwest::async_impl::client::Pending>
  invoke void @"_ZN4core3ptr57drop_in_place$LT$reqwest..async_impl..client..Pending$GT$17h8ee5a8de713fdca4E"(ptr align 8 %2)
          to label %bb2 unwind label %funclet_bb7

bb7:                                              ; preds = %funclet_bb7
; call core::ptr::drop_in_place<reqwest::async_impl::client::Client>
  call void @"_ZN4core3ptr56drop_in_place$LT$reqwest..async_impl..client..Client$GT$17h0af6548185887807E"(ptr align 8 %_1) #5 [ "funclet"(token %cleanuppad) ]
  cleanupret from %cleanuppad unwind label %funclet_bb9

funclet_bb7:                                      ; preds = %bb14
  %cleanuppad = cleanuppad within none []
  br label %bb7

bb2:                                              ; preds = %bb14
; invoke core::ptr::drop_in_place<reqwest::async_impl::client::Client>
  invoke void @"_ZN4core3ptr56drop_in_place$LT$reqwest..async_impl..client..Client$GT$17h0af6548185887807E"(ptr align 8 %_1)
          to label %bb4 unwind label %funclet_bb9

bb9:                                              ; preds = %funclet_bb9
  cleanupret from %cleanuppad1 unwind to caller

funclet_bb9:                                      ; preds = %bb7, %bb2
  %cleanuppad1 = cleanuppad within none []
  br label %bb9

bb4:                                              ; preds = %bb2
  ret void
}

; core::task::wake::Waker::noop
; Function Attrs: inlinehint uwtable
define internal align 8 ptr @_ZN4core4task4wake5Waker4noop17h714184068c0aad8fE() unnamed_addr #0 {
start:
  ret ptr @alloc_034d8ce7c7446840ac80139172d67d00
}

; core::task::wake::Context::from_waker
; Function Attrs: inlinehint uwtable
define internal void @_ZN4core4task4wake7Context10from_waker17h8c8c0ca5b4634f01E(ptr sret([32 x i8]) align 8 %_0, ptr align 8 %waker) unnamed_addr #0 {
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
define void @"_ZN4core4task4wake8RawWaker4NOOP6VTABLE28_$u7b$$u7b$closure$u7d$$u7d$17h4c2db514003e777aE"(ptr align 1 %_1, ptr %_2) unnamed_addr #0 {
start:
  ret void
}

; core::task::wake::RawWaker::NOOP::VTABLE::{{closure}}
; Function Attrs: inlinehint uwtable
define void @"_ZN4core4task4wake8RawWaker4NOOP6VTABLE28_$u7b$$u7b$closure$u7d$$u7d$17h641525f75c0b5d0cE"(ptr align 1 %_1, ptr %_2) unnamed_addr #0 {
start:
  ret void
}

; core::task::wake::RawWaker::NOOP::VTABLE::{{closure}}
; Function Attrs: inlinehint uwtable
define void @"_ZN4core4task4wake8RawWaker4NOOP6VTABLE28_$u7b$$u7b$closure$u7d$$u7d$17hb1bc70aea3680149E"(ptr align 1 %_1, ptr %_2) unnamed_addr #0 {
start:
  ret void
}

; core::task::wake::RawWaker::NOOP::VTABLE::{{closure}}
; Function Attrs: inlinehint uwtable
define { ptr, ptr } @"_ZN4core4task4wake8RawWaker4NOOP6VTABLE28_$u7b$$u7b$closure$u7d$$u7d$17hd05ec6b3a6a72803E"(ptr align 1 %_1, ptr %_2) unnamed_addr #0 {
start:
  ret { ptr, ptr } { ptr @alloc_a9789c9151c50f11596d118305db5499, ptr null }
}

; core::result::Result<T,E>::map
; Function Attrs: inlinehint uwtable
define void @"_ZN4core6result19Result$LT$T$C$E$GT$3map17h0ec41848052866dbE"(ptr sret([304 x i8]) align 8 %_0, ptr align 8 %self, ptr align 8 %op) unnamed_addr #0 {
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
  call void @"_ZN7reqwest8blocking6client6Client7request28_$u7b$$u7b$closure$u7d$$u7d$17h91265c9ea2f09ac8E"(ptr sret([304 x i8]) align 8 %_5, ptr align 8 %_6, ptr align 8 %_7)
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_0, ptr align 8 %_5, i64 304, i1 false)
  br label %bb5

bb2:                                              ; preds = %start
  %3 = getelementptr inbounds i8, ptr %self, i64 8
  %e = load ptr, ptr %3, align 8
  %4 = getelementptr inbounds i8, ptr %_0, i64 8
  store ptr %e, ptr %4, align 8
  store i64 2, ptr %_0, align 8
; call core::ptr::drop_in_place<reqwest::blocking::client::Client::request<&str>::{{closure}}>
  call void @"_ZN4core3ptr107drop_in_place$LT$reqwest..blocking..client..Client..request$LT$$RF$str$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$17h904306e8c1d44a7aE"(ptr align 8 %op)
  br label %bb5

bb5:                                              ; preds = %bb2, %bb3
  ret void

bb1:                                              ; No predecessors!
  unreachable
}

; core::result::Result<T,E>::map
; Function Attrs: inlinehint uwtable
define void @"_ZN4core6result19Result$LT$T$C$E$GT$3map17hd71f0972d296af7aE"(ptr sret([264 x i8]) align 8 %_0, ptr align 8 %self, ptr align 8 %op) unnamed_addr #0 {
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
  call void @"_ZN7reqwest10async_impl6client6Client7request28_$u7b$$u7b$closure$u7d$$u7d$17h7d5bc15954610aa3E"(ptr sret([264 x i8]) align 8 %_5, ptr align 8 %_6, ptr align 8 %_7)
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_0, ptr align 8 %_5, i64 264, i1 false)
  br label %bb5

bb2:                                              ; preds = %start
  %3 = getelementptr inbounds i8, ptr %self, i64 8
  %e = load ptr, ptr %3, align 8
  %4 = getelementptr inbounds i8, ptr %_0, i64 8
  store ptr %e, ptr %4, align 8
  store i64 2, ptr %_0, align 8
; call core::ptr::drop_in_place<reqwest::async_impl::client::Client::request<&str>::{{closure}}>
  call void @"_ZN4core3ptr109drop_in_place$LT$reqwest..async_impl..client..Client..request$LT$$RF$str$GT$..$u7b$$u7b$closure$u7d$$u7d$$GT$17hd7ba6dfd33a6e1f7E"(ptr align 8 %op)
  br label %bb5

bb5:                                              ; preds = %bb2, %bb3
  ret void

bb1:                                              ; No predecessors!
  unreachable
}

; http::extensions::Extensions::new
; Function Attrs: inlinehint uwtable
define internal align 8 ptr @_ZN4http10extensions10Extensions3new17ha92293411b1a1e29E() unnamed_addr #0 {
start:
  %_1 = alloca [8 x i8], align 8
  store ptr null, ptr %_1, align 8
  %_0 = load ptr, ptr %_1, align 8
  ret ptr %_0
}

; http::header::map::HeaderMap::new
; Function Attrs: inlinehint uwtable
define internal void @_ZN4http6header3map9HeaderMap3new17haa5b534cb6df7fb2E(ptr sret([96 x i8]) align 8 %_0) unnamed_addr #0 {
start:
; call <http::header::map::HeaderMap<T> as core::default::Default>::default
  call void @"_ZN80_$LT$http..header..map..HeaderMap$LT$T$GT$$u20$as$u20$core..default..Default$GT$7default17ha0a1516c74d57d30E"(ptr sret([96 x i8]) align 8 %_0)
  ret void
}

; <F as core::future::into_future::IntoFuture>::into_future
; Function Attrs: uwtable
define { i64, ptr } @"_ZN59_$LT$F$u20$as$u20$core..future..into_future..IntoFuture$GT$11into_future17he2c9667ff0a0db2cE"(i64 %self.0, ptr %self.1) unnamed_addr #1 {
start:
  %0 = insertvalue { i64, ptr } poison, i64 %self.0, 0
  %1 = insertvalue { i64, ptr } %0, ptr %self.1, 1
  ret { i64, ptr } %1
}

; <&mut T as core::ops::deref::DerefMut>::deref_mut
; Function Attrs: uwtable
define align 8 ptr @"_ZN60_$LT$$RF$mut$u20$T$u20$as$u20$core..ops..deref..DerefMut$GT$9deref_mut17h4a5c1eefb52134b5E"(ptr align 8 %self) unnamed_addr #1 {
start:
  %_0 = load ptr, ptr %self, align 8
  ret ptr %_0
}

; <http::version::Version as core::default::Default>::default
; Function Attrs: inlinehint uwtable
define internal i8 @"_ZN65_$LT$http..version..Version$u20$as$u20$core..default..Default$GT$7default17ha2785e7ad40616d5E"() unnamed_addr #0 {
start:
  ret i8 2
}

; <reqwest::blocking::client::Client as core::clone::Clone>::clone
; Function Attrs: inlinehint uwtable
define internal void @"_ZN72_$LT$reqwest..blocking..client..Client$u20$as$u20$core..clone..Clone$GT$5clone17h1cd7d0991ceb9522E"(ptr sret([24 x i8]) align 8 %_0, ptr align 8 %self) unnamed_addr #0 {
start:
  %_2 = alloca [24 x i8], align 8
; call <reqwest::blocking::client::ClientHandle as core::clone::Clone>::clone
  call void @"_ZN78_$LT$reqwest..blocking..client..ClientHandle$u20$as$u20$core..clone..Clone$GT$5clone17h3536814788d42dc5E"(ptr sret([24 x i8]) align 8 %_2, ptr align 8 %self)
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_0, ptr align 8 %_2, i64 24, i1 false)
  ret void
}

; <reqwest::blocking::client::Timeout as core::clone::Clone>::clone
; Function Attrs: inlinehint uwtable
define internal { i64, i32 } @"_ZN73_$LT$reqwest..blocking..client..Timeout$u20$as$u20$core..clone..Clone$GT$5clone17h995204b0580bb732E"(ptr align 8 %self) unnamed_addr #0 {
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
define internal ptr @"_ZN74_$LT$reqwest..async_impl..client..Client$u20$as$u20$core..clone..Clone$GT$5clone17h8070770bd0e3b98eE"(ptr align 8 %self) unnamed_addr #0 {
start:
; call <alloc::sync::Arc<T,A> as core::clone::Clone>::clone
  %_2 = call ptr @"_ZN68_$LT$alloc..sync..Arc$LT$T$C$A$GT$$u20$as$u20$core..clone..Clone$GT$5clone17h7bc183f4986daa0dE"(ptr align 8 %self)
  ret ptr %_2
}

; <reqwest::blocking::client::ClientHandle as core::clone::Clone>::clone
; Function Attrs: inlinehint uwtable
define internal void @"_ZN78_$LT$reqwest..blocking..client..ClientHandle$u20$as$u20$core..clone..Clone$GT$5clone17h3536814788d42dc5E"(ptr sret([24 x i8]) align 8 %_0, ptr align 8 %self) unnamed_addr #0 {
start:
  %_3 = getelementptr inbounds i8, ptr %self, i64 8
; call <reqwest::blocking::client::Timeout as core::clone::Clone>::clone
  %0 = call { i64, i32 } @"_ZN73_$LT$reqwest..blocking..client..Timeout$u20$as$u20$core..clone..Clone$GT$5clone17h995204b0580bb732E"(ptr align 8 %_3)
  %_2.0 = extractvalue { i64, i32 } %0, 0
  %_2.1 = extractvalue { i64, i32 } %0, 1
; call <alloc::sync::Arc<T,A> as core::clone::Clone>::clone
  %_4 = call ptr @"_ZN68_$LT$alloc..sync..Arc$LT$T$C$A$GT$$u20$as$u20$core..clone..Clone$GT$5clone17h6b0f8d1ceb08b6bcE"(ptr align 8 %self)
  %1 = getelementptr inbounds i8, ptr %_0, i64 8
  store i64 %_2.0, ptr %1, align 8
  %2 = getelementptr inbounds i8, ptr %1, i64 8
  store i32 %_2.1, ptr %2, align 8
  store ptr %_4, ptr %_0, align 8
  ret void
}

; reqwest::async_impl::client::Client::get
; Function Attrs: uwtable
define void @_ZN7reqwest10async_impl6client6Client3get17h45319080d5f843fcE(ptr sret([272 x i8]) align 8 %_0, ptr align 8 %self, ptr align 1 %url.0, i64 %url.1) unnamed_addr #1 {
start:
  %0 = alloca [24 x i8], align 8
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %0, ptr align 8 @1, i64 24, i1 false)
; call reqwest::async_impl::client::Client::request
  call void @_ZN7reqwest10async_impl6client6Client7request17hb1332ad8325b2346E(ptr sret([272 x i8]) align 8 %_0, ptr align 8 %self, ptr align 8 %0, ptr align 1 %url.0, i64 %url.1)
  ret void
}

; reqwest::async_impl::client::Client::request
; Function Attrs: uwtable
define void @_ZN7reqwest10async_impl6client6Client7request17hb1332ad8325b2346E(ptr sret([272 x i8]) align 8 %_0, ptr align 8 %self, ptr align 8 %method, ptr align 1 %url.0, i64 %url.1) unnamed_addr #1 personality ptr @__CxxFrameHandler3 {
start:
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
  invoke void @"_ZN60_$LT$$RF$str$u20$as$u20$reqwest..into_url..IntoUrlSealed$GT$8into_url17hc31bf897d9923d7dE"(ptr sret([88 x i8]) align 8 %_5, ptr align 1 %url.0, i64 %url.1)
          to label %bb1 unwind label %funclet_bb9

bb9:                                              ; preds = %funclet_bb9
  %0 = load i8, ptr %_10, align 1
  %1 = trunc i8 %0 to i1
  br i1 %1, label %bb8, label %bb5

funclet_bb9:                                      ; preds = %bb6, %bb7_cleanup_trampoline_bb9, %bb1, %start
  %cleanuppad = cleanuppad within none []
  br label %bb9

bb1:                                              ; preds = %start
  store i8 0, ptr %_10, align 1
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_6, ptr align 8 %method, i64 24, i1 false)
; invoke core::result::Result<T,E>::map
  invoke void @"_ZN4core6result19Result$LT$T$C$E$GT$3map17hd71f0972d296af7aE"(ptr sret([264 x i8]) align 8 %req, ptr align 8 %_5, ptr align 8 %_6)
          to label %bb2 unwind label %funclet_bb9

bb2:                                              ; preds = %bb1
  store i8 1, ptr %_9, align 1
; invoke <reqwest::async_impl::client::Client as core::clone::Clone>::clone
  %_7 = invoke ptr @"_ZN74_$LT$reqwest..async_impl..client..Client$u20$as$u20$core..clone..Clone$GT$5clone17h8070770bd0e3b98eE"(ptr align 8 %self)
          to label %bb3 unwind label %funclet_bb7

bb7:                                              ; preds = %funclet_bb7
  %2 = load i8, ptr %_9, align 1
  %3 = trunc i8 %2 to i1
  br i1 %3, label %bb6, label %bb7_cleanup_trampoline_bb9

funclet_bb7:                                      ; preds = %bb3, %bb2
  %cleanuppad1 = cleanuppad within none []
  br label %bb7

bb3:                                              ; preds = %bb2
  store i8 0, ptr %_9, align 1
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_8, ptr align 8 %req, i64 264, i1 false)
; invoke reqwest::async_impl::request::RequestBuilder::new
  invoke void @_ZN7reqwest10async_impl7request14RequestBuilder3new17h2a35b4471788f9b6E(ptr sret([272 x i8]) align 8 %_0, ptr %_7, ptr align 8 %_8)
          to label %bb4 unwind label %funclet_bb7

bb4:                                              ; preds = %bb3
  store i8 0, ptr %_9, align 1
  ret void

bb7_cleanup_trampoline_bb9:                       ; preds = %bb7
  cleanupret from %cleanuppad1 unwind label %funclet_bb9

bb6:                                              ; preds = %bb7
; call core::ptr::drop_in_place<core::result::Result<reqwest::async_impl::request::Request,reqwest::error::Error>>
  call void @"_ZN4core3ptr110drop_in_place$LT$core..result..Result$LT$reqwest..async_impl..request..Request$C$reqwest..error..Error$GT$$GT$17h31bb0087a3113920E"(ptr align 8 %req) #5 [ "funclet"(token %cleanuppad1) ]
  cleanupret from %cleanuppad1 unwind label %funclet_bb9

bb5:                                              ; preds = %bb8, %bb9
  cleanupret from %cleanuppad unwind to caller

bb8:                                              ; preds = %bb9
; call core::ptr::drop_in_place<http::method::Method>
  call void @"_ZN4core3ptr41drop_in_place$LT$http..method..Method$GT$17h2d651b10f05c5163E"(ptr align 8 %method) #5 [ "funclet"(token %cleanuppad) ]
  br label %bb5
}

; reqwest::async_impl::client::Client::request::{{closure}}
; Function Attrs: inlinehint uwtable
define void @"_ZN7reqwest10async_impl6client6Client7request28_$u7b$$u7b$closure$u7d$$u7d$17h7d5bc15954610aa3E"(ptr sret([264 x i8]) align 8 %_0, ptr align 8 %_1, ptr align 8 %url) unnamed_addr #0 {
start:
  %_3 = alloca [24 x i8], align 8
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_3, ptr align 8 %_1, i64 24, i1 false)
; call reqwest::async_impl::request::Request::new
  call void @_ZN7reqwest10async_impl7request7Request3new17hc9979073a91ea843E(ptr sret([264 x i8]) align 8 %_0, ptr align 8 %_3, ptr align 8 %url)
  ret void
}

; reqwest::async_impl::request::Request::new
; Function Attrs: inlinehint uwtable
define internal void @_ZN7reqwest10async_impl7request7Request3new17hc9979073a91ea843E(ptr sret([264 x i8]) align 8 %_0, ptr align 8 %method, ptr align 8 %url) unnamed_addr #0 personality ptr @__CxxFrameHandler3 {
start:
  %_6 = alloca [40 x i8], align 8
  %_5 = alloca [96 x i8], align 8
  %_4 = alloca [88 x i8], align 8
  %_3 = alloca [24 x i8], align 8
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_3, ptr align 8 %method, i64 24, i1 false)
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_4, ptr align 8 %url, i64 88, i1 false)
; invoke http::header::map::HeaderMap::new
  invoke void @_ZN4http6header3map9HeaderMap3new17haa5b534cb6df7fb2E(ptr sret([96 x i8]) align 8 %_5)
          to label %bb1 unwind label %funclet_bb6

bb6:                                              ; preds = %funclet_bb6
; call core::ptr::drop_in_place<url::Url>
  call void @"_ZN4core3ptr29drop_in_place$LT$url..Url$GT$17h4960efdc1279e5aeE"(ptr align 8 %_4) #5 [ "funclet"(token %cleanuppad) ]
; call core::ptr::drop_in_place<http::method::Method>
  call void @"_ZN4core3ptr41drop_in_place$LT$http..method..Method$GT$17h2d651b10f05c5163E"(ptr align 8 %_3) #5 [ "funclet"(token %cleanuppad) ]
  cleanupret from %cleanuppad unwind to caller

funclet_bb6:                                      ; preds = %bb4, %start
  %cleanuppad = cleanuppad within none []
  br label %bb6

bb1:                                              ; preds = %start
  store i64 0, ptr %_6, align 8
; invoke <http::version::Version as core::default::Default>::default
  %_7 = invoke i8 @"_ZN65_$LT$http..version..Version$u20$as$u20$core..default..Default$GT$7default17ha2785e7ad40616d5E"()
          to label %bb2 unwind label %funclet_bb4

bb4:                                              ; preds = %funclet_bb4
; call core::ptr::drop_in_place<core::option::Option<reqwest::async_impl::body::Body>>
  call void @"_ZN4core3ptr80drop_in_place$LT$core..option..Option$LT$reqwest..async_impl..body..Body$GT$$GT$17hb4c33df2e2e10187E"(ptr align 8 %_6) #5 [ "funclet"(token %cleanuppad1) ]
; call core::ptr::drop_in_place<http::header::map::HeaderMap>
  call void @"_ZN4core3ptr49drop_in_place$LT$http..header..map..HeaderMap$GT$17h761f53362e975f18E"(ptr align 8 %_5) #5 [ "funclet"(token %cleanuppad1) ]
  cleanupret from %cleanuppad1 unwind label %funclet_bb6

funclet_bb4:                                      ; preds = %bb2, %bb1
  %cleanuppad1 = cleanuppad within none []
  br label %bb4

bb2:                                              ; preds = %bb1
; invoke http::extensions::Extensions::new
  %_8 = invoke align 8 ptr @_ZN4http10extensions10Extensions3new17ha92293411b1a1e29E()
          to label %bb3 unwind label %funclet_bb4

bb3:                                              ; preds = %bb2
  %0 = getelementptr inbounds i8, ptr %_0, i64 224
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %0, ptr align 8 %_3, i64 24, i1 false)
  %1 = getelementptr inbounds i8, ptr %_0, i64 136
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %1, ptr align 8 %_4, i64 88, i1 false)
  %2 = getelementptr inbounds i8, ptr %_0, i64 40
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %2, ptr align 8 %_5, i64 96, i1 false)
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_0, ptr align 8 %_6, i64 40, i1 false)
  %3 = getelementptr inbounds i8, ptr %_0, i64 256
  store i8 %_7, ptr %3, align 8
  %4 = getelementptr inbounds i8, ptr %_0, i64 248
  store ptr %_8, ptr %4, align 8
  ret void
}

; reqwest::blocking::client::Client::get
; Function Attrs: uwtable
define void @_ZN7reqwest8blocking6client6Client3get17h04566feb234cdb7eE(ptr sret([328 x i8]) align 8 %_0, ptr align 8 %self, ptr align 1 %url.0, i64 %url.1) unnamed_addr #1 {
start:
  %0 = alloca [24 x i8], align 8
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %0, ptr align 8 @1, i64 24, i1 false)
; call reqwest::blocking::client::Client::request
  call void @_ZN7reqwest8blocking6client6Client7request17h7e40fa97ff883c27E(ptr sret([328 x i8]) align 8 %_0, ptr align 8 %self, ptr align 8 %0, ptr align 1 %url.0, i64 %url.1)
  ret void
}

; reqwest::blocking::client::Client::request
; Function Attrs: uwtable
define void @_ZN7reqwest8blocking6client6Client7request17h7e40fa97ff883c27E(ptr sret([328 x i8]) align 8 %_0, ptr align 8 %self, ptr align 8 %method, ptr align 1 %url.0, i64 %url.1) unnamed_addr #1 personality ptr @__CxxFrameHandler3 {
start:
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
  invoke void @"_ZN60_$LT$$RF$str$u20$as$u20$reqwest..into_url..IntoUrlSealed$GT$8into_url17hc31bf897d9923d7dE"(ptr sret([88 x i8]) align 8 %_5, ptr align 1 %url.0, i64 %url.1)
          to label %bb1 unwind label %funclet_bb9

bb9:                                              ; preds = %funclet_bb9
  %0 = load i8, ptr %_10, align 1
  %1 = trunc i8 %0 to i1
  br i1 %1, label %bb8, label %bb5

funclet_bb9:                                      ; preds = %bb6, %bb7_cleanup_trampoline_bb9, %bb1, %start
  %cleanuppad = cleanuppad within none []
  br label %bb9

bb1:                                              ; preds = %start
  store i8 0, ptr %_10, align 1
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_6, ptr align 8 %method, i64 24, i1 false)
; invoke core::result::Result<T,E>::map
  invoke void @"_ZN4core6result19Result$LT$T$C$E$GT$3map17h0ec41848052866dbE"(ptr sret([304 x i8]) align 8 %req, ptr align 8 %_5, ptr align 8 %_6)
          to label %bb2 unwind label %funclet_bb9

bb2:                                              ; preds = %bb1
  store i8 1, ptr %_9, align 1
; invoke <reqwest::blocking::client::Client as core::clone::Clone>::clone
  invoke void @"_ZN72_$LT$reqwest..blocking..client..Client$u20$as$u20$core..clone..Clone$GT$5clone17h1cd7d0991ceb9522E"(ptr sret([24 x i8]) align 8 %_7, ptr align 8 %self)
          to label %bb3 unwind label %funclet_bb7

bb7:                                              ; preds = %funclet_bb7
  %2 = load i8, ptr %_9, align 1
  %3 = trunc i8 %2 to i1
  br i1 %3, label %bb6, label %bb7_cleanup_trampoline_bb9

funclet_bb7:                                      ; preds = %bb3, %bb2
  %cleanuppad1 = cleanuppad within none []
  br label %bb7

bb3:                                              ; preds = %bb2
  store i8 0, ptr %_9, align 1
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_8, ptr align 8 %req, i64 304, i1 false)
; invoke reqwest::blocking::request::RequestBuilder::new
  invoke void @_ZN7reqwest8blocking7request14RequestBuilder3new17h760a82a405d52f5dE(ptr sret([328 x i8]) align 8 %_0, ptr align 8 %_7, ptr align 8 %_8)
          to label %bb4 unwind label %funclet_bb7

bb4:                                              ; preds = %bb3
  store i8 0, ptr %_9, align 1
  ret void

bb7_cleanup_trampoline_bb9:                       ; preds = %bb7
  cleanupret from %cleanuppad1 unwind label %funclet_bb9

bb6:                                              ; preds = %bb7
; call core::ptr::drop_in_place<core::result::Result<reqwest::blocking::request::Request,reqwest::error::Error>>
  call void @"_ZN4core3ptr108drop_in_place$LT$core..result..Result$LT$reqwest..blocking..request..Request$C$reqwest..error..Error$GT$$GT$17h46888f0e9084fff1E"(ptr align 8 %req) #5 [ "funclet"(token %cleanuppad1) ]
  cleanupret from %cleanuppad1 unwind label %funclet_bb9

bb5:                                              ; preds = %bb8, %bb9
  cleanupret from %cleanuppad unwind to caller

bb8:                                              ; preds = %bb9
; call core::ptr::drop_in_place<http::method::Method>
  call void @"_ZN4core3ptr41drop_in_place$LT$http..method..Method$GT$17h2d651b10f05c5163E"(ptr align 8 %method) #5 [ "funclet"(token %cleanuppad) ]
  br label %bb5
}

; reqwest::blocking::client::Client::request::{{closure}}
; Function Attrs: inlinehint uwtable
define void @"_ZN7reqwest8blocking6client6Client7request28_$u7b$$u7b$closure$u7d$$u7d$17h91265c9ea2f09ac8E"(ptr sret([304 x i8]) align 8 %_0, ptr align 8 %_1, ptr align 8 %url) unnamed_addr #0 {
start:
  %_3 = alloca [24 x i8], align 8
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_3, ptr align 8 %_1, i64 24, i1 false)
; call reqwest::blocking::request::Request::new
  call void @_ZN7reqwest8blocking7request7Request3new17hb710bd0db2a84424E(ptr sret([304 x i8]) align 8 %_0, ptr align 8 %_3, ptr align 8 %url)
  ret void
}

; reqwest::blocking::request::Request::new
; Function Attrs: inlinehint uwtable
define internal void @_ZN7reqwest8blocking7request7Request3new17hb710bd0db2a84424E(ptr sret([304 x i8]) align 8 %_0, ptr align 8 %method, ptr align 8 %url) unnamed_addr #0 personality ptr @__CxxFrameHandler3 {
start:
  %_4 = alloca [264 x i8], align 8
  %_3 = alloca [40 x i8], align 8
  store i64 2, ptr %_3, align 8
; invoke reqwest::async_impl::request::Request::new
  invoke void @_ZN7reqwest10async_impl7request7Request3new17hc9979073a91ea843E(ptr sret([264 x i8]) align 8 %_4, ptr align 8 %method, ptr align 8 %url)
          to label %bb1 unwind label %funclet_bb2

bb2:                                              ; preds = %funclet_bb2
; call core::ptr::drop_in_place<core::option::Option<reqwest::blocking::body::Body>>
  call void @"_ZN4core3ptr78drop_in_place$LT$core..option..Option$LT$reqwest..blocking..body..Body$GT$$GT$17hc05a19dc7ee303acE"(ptr align 8 %_3) #5 [ "funclet"(token %cleanuppad) ]
  cleanupret from %cleanuppad unwind to caller

funclet_bb2:                                      ; preds = %start
  %cleanuppad = cleanuppad within none []
  br label %bb2

bb1:                                              ; preds = %start
  %0 = getelementptr inbounds i8, ptr %_0, i64 264
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %0, ptr align 8 %_3, i64 40, i1 false)
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_0, ptr align 8 %_4, i64 264, i1 false)
  ret void
}

; raw_http_reqwest::do_send
; Function Attrs: uwtable
define void @_ZN16raw_http_reqwest7do_send17h5ee245a06a5419e4E(ptr sret([32 x i8]) align 8 %_0) unnamed_addr #1 {
start:
  %0 = getelementptr inbounds i8, ptr %_0, i64 24
  store i8 0, ptr %0, align 8
  ret void
}

; raw_http_reqwest::do_send::{{closure}}
; Function Attrs: inlinehint uwtable
define zeroext i1 @"_ZN16raw_http_reqwest7do_send28_$u7b$$u7b$closure$u7d$$u7d$17h5ef0c5210f1785c1E"(ptr align 8 %0, ptr align 8 %_2) unnamed_addr #0 personality ptr @__CxxFrameHandler3 {
start:
  %_task_context = alloca [8 x i8], align 8
  %result = alloca [136 x i8], align 8
  %_8 = alloca [136 x i8], align 8
  %_6 = alloca [272 x i8], align 8
  %_3 = alloca [136 x i8], align 8
  %_0 = alloca [1 x i8], align 1
  %_1 = alloca [8 x i8], align 8
  store ptr %0, ptr %_1, align 8
  %_16 = load ptr, ptr %_1, align 8
  %1 = getelementptr inbounds i8, ptr %_16, i64 24
  %2 = load i8, ptr %1, align 8
  %_15 = zext i8 %2 to i32
  switch i32 %_15, label %bb9 [
    i32 0, label %bb1
    i32 1, label %bb20
    i32 2, label %bb19
    i32 3, label %bb18
  ]

bb9:                                              ; preds = %start
  unreachable

bb1:                                              ; preds = %start
  store ptr %_2, ptr %_task_context, align 8
  %_17 = load ptr, ptr %_1, align 8
; invoke reqwest::async_impl::client::Client::new
  %3 = invoke ptr @_ZN7reqwest10async_impl6client6Client3new17h002af87b15b4de93E()
          to label %bb2 unwind label %funclet_bb17

bb20:                                             ; preds = %bb20, %start
  br i1 false, label %bb20, label %panic

bb19:                                             ; preds = %bb19, %start
  br i1 false, label %bb19, label %panic2

bb18:                                             ; preds = %start
  store ptr %_2, ptr %_task_context, align 8
  br label %bb6

bb17:                                             ; preds = %funclet_bb17
  %_27 = load ptr, ptr %_1, align 8
  %4 = getelementptr inbounds i8, ptr %_27, i64 24
  store i8 2, ptr %4, align 8
  cleanupret from %cleanuppad unwind to caller

funclet_bb17:                                     ; preds = %bb16, %bb13, %bb1
  %cleanuppad = cleanuppad within none []
  br label %bb17

bb2:                                              ; preds = %bb1
  store ptr %3, ptr %_17, align 8
  %_18 = load ptr, ptr %_1, align 8
; invoke reqwest::async_impl::client::Client::get
  invoke void @_ZN7reqwest10async_impl6client6Client3get17h45319080d5f843fcE(ptr sret([272 x i8]) align 8 %_6, ptr align 8 %_18, ptr align 1 @alloc_6ad81882bf157ce64a1f79ee864cdd93, i64 18)
          to label %bb3 unwind label %funclet_bb16

bb16:                                             ; preds = %funclet_bb16
  %_26 = load ptr, ptr %_1, align 8
; call core::ptr::drop_in_place<reqwest::async_impl::client::Client>
  call void @"_ZN4core3ptr56drop_in_place$LT$reqwest..async_impl..client..Client$GT$17h0af6548185887807E"(ptr align 8 %_26) #5 [ "funclet"(token %cleanuppad1) ]
  cleanupret from %cleanuppad1 unwind label %funclet_bb17

funclet_bb16:                                     ; preds = %bb15, %bb12, %bb11, %bb4, %bb3, %bb2
  %cleanuppad1 = cleanuppad within none []
  br label %bb16

bb3:                                              ; preds = %bb2
; invoke reqwest::async_impl::request::RequestBuilder::send
  %5 = invoke { i64, ptr } @_ZN7reqwest10async_impl7request14RequestBuilder4send17hca2adc12c5834e3aE(ptr align 8 %_6)
          to label %bb4 unwind label %funclet_bb16

bb4:                                              ; preds = %bb3
  %_5.0 = extractvalue { i64, ptr } %5, 0
  %_5.1 = extractvalue { i64, ptr } %5, 1
; invoke <F as core::future::into_future::IntoFuture>::into_future
  %6 = invoke { i64, ptr } @"_ZN59_$LT$F$u20$as$u20$core..future..into_future..IntoFuture$GT$11into_future17he2c9667ff0a0db2cE"(i64 %_5.0, ptr %_5.1)
          to label %bb5 unwind label %funclet_bb16

bb5:                                              ; preds = %bb4
  %_4.0 = extractvalue { i64, ptr } %6, 0
  %_4.1 = extractvalue { i64, ptr } %6, 1
  %_19 = load ptr, ptr %_1, align 8
  %7 = getelementptr inbounds i8, ptr %_19, i64 8
  store i64 %_4.0, ptr %7, align 8
  %8 = getelementptr inbounds i8, ptr %7, i64 8
  store ptr %_4.1, ptr %8, align 8
  br label %bb6

bb6:                                              ; preds = %bb18, %bb5
  %_20 = load ptr, ptr %_1, align 8
  %_10 = getelementptr inbounds i8, ptr %_20, i64 8
  br label %bb7

panic:                                            ; preds = %bb20
; call core::panicking::panic_const::panic_const_async_fn_resumed
  call void @_ZN4core9panicking11panic_const28panic_const_async_fn_resumed17h009012cf7da8298dE(ptr align 8 @alloc_9c46cdc72b2e47ad975360fa9a270d09) #6
  unreachable

panic2:                                           ; preds = %bb19
; call core::panicking::panic_const::panic_const_async_fn_resumed_panic
  call void @_ZN4core9panicking11panic_const34panic_const_async_fn_resumed_panic17h0dd5db8d3c6f4651E(ptr align 8 @alloc_9c46cdc72b2e47ad975360fa9a270d09) #6
  unreachable

bb15:                                             ; preds = %funclet_bb15
  %_25 = load ptr, ptr %_1, align 8
  %9 = getelementptr inbounds i8, ptr %_25, i64 8
; call core::ptr::drop_in_place<reqwest::async_impl::client::Pending>
  call void @"_ZN4core3ptr57drop_in_place$LT$reqwest..async_impl..client..Pending$GT$17h8ee5a8de713fdca4E"(ptr align 8 %9) #5 [ "funclet"(token %cleanuppad3) ]
  cleanupret from %cleanuppad3 unwind label %funclet_bb16

funclet_bb15:                                     ; preds = %bb7
  %cleanuppad3 = cleanuppad within none []
  br label %bb15

bb7:                                              ; preds = %bb6
  %_11 = load ptr, ptr %_task_context, align 8
; invoke <reqwest::async_impl::client::Pending as core::future::future::Future>::poll
  invoke void @"_ZN85_$LT$reqwest..async_impl..client..Pending$u20$as$u20$core..future..future..Future$GT$4poll17h3b880a10240d43cfE"(ptr sret([136 x i8]) align 8 %_8, ptr align 8 %_10, ptr align 8 %_11)
          to label %bb8 unwind label %funclet_bb15

bb8:                                              ; preds = %bb7
  %10 = load i64, ptr %_8, align 8
  %11 = icmp eq i64 %10, 4
  %_12 = select i1 %11, i64 1, i64 0
  %12 = icmp eq i64 %_12, 0
  br i1 %12, label %bb11, label %bb10

bb11:                                             ; preds = %bb8
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %result, ptr align 8 %_8, i64 136, i1 false)
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_3, ptr align 8 %result, i64 136, i1 false)
  %_22 = load ptr, ptr %_1, align 8
  %13 = getelementptr inbounds i8, ptr %_22, i64 8
; invoke core::ptr::drop_in_place<reqwest::async_impl::client::Pending>
  invoke void @"_ZN4core3ptr57drop_in_place$LT$reqwest..async_impl..client..Pending$GT$17h8ee5a8de713fdca4E"(ptr align 8 %13)
          to label %bb12 unwind label %funclet_bb16

bb10:                                             ; preds = %bb8
  store i8 1, ptr %_0, align 1
  %_21 = load ptr, ptr %_1, align 8
  %14 = getelementptr inbounds i8, ptr %_21, i64 24
  store i8 3, ptr %14, align 8
  %15 = load i8, ptr %_0, align 1
  %16 = trunc i8 %15 to i1
  ret i1 %16

bb12:                                             ; preds = %bb11
; invoke core::ptr::drop_in_place<core::result::Result<reqwest::async_impl::response::Response,reqwest::error::Error>>
  invoke void @"_ZN4core3ptr112drop_in_place$LT$core..result..Result$LT$reqwest..async_impl..response..Response$C$reqwest..error..Error$GT$$GT$17h736911f91e59a316E"(ptr align 8 %_3)
          to label %bb13 unwind label %funclet_bb16

bb13:                                             ; preds = %bb12
  %_23 = load ptr, ptr %_1, align 8
; invoke core::ptr::drop_in_place<reqwest::async_impl::client::Client>
  invoke void @"_ZN4core3ptr56drop_in_place$LT$reqwest..async_impl..client..Client$GT$17h0af6548185887807E"(ptr align 8 %_23)
          to label %bb14 unwind label %funclet_bb17

bb14:                                             ; preds = %bb13
  store i8 0, ptr %_0, align 1
  %_24 = load ptr, ptr %_1, align 8
  %17 = getelementptr inbounds i8, ptr %_24, i64 24
  store i8 1, ptr %17, align 8
  %18 = load i8, ptr %_0, align 1
  %19 = trunc i8 %18 to i1
  ret i1 %19
}

; raw_http_reqwest::do_blocking_send
; Function Attrs: uwtable
define void @_ZN16raw_http_reqwest16do_blocking_send17h4e28722ce2982856E() unnamed_addr #1 personality ptr @__CxxFrameHandler3 {
start:
  %_3 = alloca [328 x i8], align 8
  %_2 = alloca [176 x i8], align 8
  %client = alloca [24 x i8], align 8
; call reqwest::blocking::client::Client::new
  call void @_ZN7reqwest8blocking6client6Client3new17h5040d938b90bba96E(ptr sret([24 x i8]) align 8 %client)
; invoke reqwest::blocking::client::Client::get
  invoke void @_ZN7reqwest8blocking6client6Client3get17h04566feb234cdb7eE(ptr sret([328 x i8]) align 8 %_3, ptr align 8 %client, ptr align 1 @alloc_6ad81882bf157ce64a1f79ee864cdd93, i64 18)
          to label %bb2 unwind label %funclet_bb6

bb6:                                              ; preds = %funclet_bb6
; call core::ptr::drop_in_place<reqwest::blocking::client::Client>
  call void @"_ZN4core3ptr54drop_in_place$LT$reqwest..blocking..client..Client$GT$17h52a2f1acad4939c9E"(ptr align 8 %client) #5 [ "funclet"(token %cleanuppad) ]
  cleanupret from %cleanuppad unwind to caller

funclet_bb6:                                      ; preds = %bb3, %bb2, %start
  %cleanuppad = cleanuppad within none []
  br label %bb6

bb2:                                              ; preds = %start
; invoke reqwest::blocking::request::RequestBuilder::send
  invoke void @_ZN7reqwest8blocking7request14RequestBuilder4send17h321b79deb49694bfE(ptr sret([176 x i8]) align 8 %_2, ptr align 8 %_3)
          to label %bb3 unwind label %funclet_bb6

bb3:                                              ; preds = %bb2
; invoke core::ptr::drop_in_place<core::result::Result<reqwest::blocking::response::Response,reqwest::error::Error>>
  invoke void @"_ZN4core3ptr110drop_in_place$LT$core..result..Result$LT$reqwest..blocking..response..Response$C$reqwest..error..Error$GT$$GT$17he89259276819211bE"(ptr align 8 %_2)
          to label %bb4 unwind label %funclet_bb6

bb4:                                              ; preds = %bb3
; call core::ptr::drop_in_place<reqwest::blocking::client::Client>
  call void @"_ZN4core3ptr54drop_in_place$LT$reqwest..blocking..client..Client$GT$17h52a2f1acad4939c9E"(ptr align 8 %client)
  ret void
}

; raw_http_reqwest::drive_do_send_once
; Function Attrs: uwtable
define void @_ZN16raw_http_reqwest18drive_do_send_once17h89698c3e80f13d5fE() unnamed_addr #1 personality ptr @__CxxFrameHandler3 {
start:
  %_10 = alloca [8 x i8], align 8
  %cx = alloca [32 x i8], align 8
  %_3 = alloca [32 x i8], align 8
  %fut = alloca [8 x i8], align 8
; call raw_http_reqwest::do_send
  call void @_ZN16raw_http_reqwest7do_send17h5ee245a06a5419e4E(ptr sret([32 x i8]) align 8 %_3)
  store ptr %_3, ptr %_10, align 8
  %0 = load ptr, ptr %_10, align 8
  store ptr %0, ptr %fut, align 8
; invoke core::task::wake::Waker::noop
  %waker = invoke align 8 ptr @_ZN4core4task4wake5Waker4noop17h714184068c0aad8fE()
          to label %bb2 unwind label %funclet_bb7

bb7:                                              ; preds = %funclet_bb7
; call core::ptr::drop_in_place<raw_http_reqwest::do_send::{{closure}}>
  call void @"_ZN4core3ptr75drop_in_place$LT$raw_http_reqwest..do_send..$u7b$$u7b$closure$u7d$$u7d$$GT$17h302c5163c1aa99dcE"(ptr align 8 %_3) #5 [ "funclet"(token %cleanuppad) ]
  cleanupret from %cleanuppad unwind to caller

funclet_bb7:                                      ; preds = %bb3, %bb4, %bb2, %start
  %cleanuppad = cleanuppad within none []
  br label %bb7

bb2:                                              ; preds = %start
; invoke core::task::wake::Context::from_waker
  invoke void @_ZN4core4task4wake7Context10from_waker17h8c8c0ca5b4634f01E(ptr sret([32 x i8]) align 8 %cx, ptr align 8 %waker)
          to label %bb3 unwind label %funclet_bb7

bb3:                                              ; preds = %bb2
; invoke <&mut T as core::ops::deref::DerefMut>::deref_mut
  %pointer.i1 = invoke align 8 ptr @"_ZN60_$LT$$RF$mut$u20$T$u20$as$u20$core..ops..deref..DerefMut$GT$9deref_mut17h4a5c1eefb52134b5E"(ptr align 8 %fut)
          to label %"_ZN4core3pin14Pin$LT$Ptr$GT$6as_mut17he05d3ec1ddc0ceeeE.exit" unwind label %funclet_bb7

"_ZN4core3pin14Pin$LT$Ptr$GT$6as_mut17he05d3ec1ddc0ceeeE.exit": ; preds = %bb3
  br label %bb4

bb4:                                              ; preds = %"_ZN4core3pin14Pin$LT$Ptr$GT$6as_mut17he05d3ec1ddc0ceeeE.exit"
; invoke raw_http_reqwest::do_send::{{closure}}
  %_6 = invoke zeroext i1 @"_ZN16raw_http_reqwest7do_send28_$u7b$$u7b$closure$u7d$$u7d$17h5ef0c5210f1785c1E"(ptr align 8 %pointer.i1, ptr align 8 %cx)
          to label %bb5 unwind label %funclet_bb7

bb5:                                              ; preds = %bb4
; call core::ptr::drop_in_place<raw_http_reqwest::do_send::{{closure}}>
  call void @"_ZN4core3ptr75drop_in_place$LT$raw_http_reqwest..do_send..$u7b$$u7b$closure$u7d$$u7d$$GT$17h302c5163c1aa99dcE"(ptr align 8 %_3)
  ret void
}

declare i32 @__CxxFrameHandler3(...) unnamed_addr #2

; core::ptr::drop_in_place<http::method::Method>
; Function Attrs: uwtable
declare void @"_ZN4core3ptr41drop_in_place$LT$http..method..Method$GT$17h2d651b10f05c5163E"(ptr align 8) unnamed_addr #1

; core::ptr::drop_in_place<reqwest::error::Error>
; Function Attrs: uwtable
declare void @"_ZN4core3ptr42drop_in_place$LT$reqwest..error..Error$GT$17ha8734def48176607E"(ptr align 8) unnamed_addr #1

; core::ptr::drop_in_place<reqwest::async_impl::response::Response>
; Function Attrs: uwtable
declare void @"_ZN4core3ptr60drop_in_place$LT$reqwest..async_impl..response..Response$GT$17h75c48e7e34ebe94aE"(ptr align 8) unnamed_addr #1

; core::ptr::drop_in_place<core::option::Option<core::pin::Pin<alloc::boxed::Box<dyn futures_io::if_std::AsyncRead+core::marker::Sync+core::marker::Send>>>>
; Function Attrs: uwtable
declare void @"_ZN4core3ptr179drop_in_place$LT$core..option..Option$LT$core..pin..Pin$LT$alloc..boxed..Box$LT$dyn$u20$futures_io..if_std..AsyncRead$u2b$core..marker..Sync$u2b$core..marker..Send$GT$$GT$$GT$$GT$17hab6f516f4e5d2633E"(ptr align 8) unnamed_addr #1

; core::ptr::drop_in_place<reqwest::blocking::client::KeepCoreThreadAlive>
; Function Attrs: uwtable
declare void @"_ZN4core3ptr67drop_in_place$LT$reqwest..blocking..client..KeepCoreThreadAlive$GT$17h22f341cced4ba138E"(ptr align 8) unnamed_addr #1

; core::ptr::drop_in_place<reqwest::async_impl::client::Pending>
; Function Attrs: uwtable
declare void @"_ZN4core3ptr57drop_in_place$LT$reqwest..async_impl..client..Pending$GT$17h8ee5a8de713fdca4E"(ptr align 8) unnamed_addr #1

; core::ptr::drop_in_place<reqwest::async_impl::client::Client>
; Function Attrs: uwtable
declare void @"_ZN4core3ptr56drop_in_place$LT$reqwest..async_impl..client..Client$GT$17h0af6548185887807E"(ptr align 8) unnamed_addr #1

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: readwrite)
declare void @llvm.memcpy.p0.p0.i64(ptr noalias nocapture writeonly, ptr noalias nocapture readonly, i64, i1 immarg) #3

; <http::header::map::HeaderMap<T> as core::default::Default>::default
; Function Attrs: uwtable
declare void @"_ZN80_$LT$http..header..map..HeaderMap$LT$T$GT$$u20$as$u20$core..default..Default$GT$7default17ha0a1516c74d57d30E"(ptr sret([96 x i8]) align 8) unnamed_addr #1

; <alloc::sync::Arc<T,A> as core::clone::Clone>::clone
; Function Attrs: inlinehint uwtable
declare ptr @"_ZN68_$LT$alloc..sync..Arc$LT$T$C$A$GT$$u20$as$u20$core..clone..Clone$GT$5clone17h7bc183f4986daa0dE"(ptr align 8) unnamed_addr #0

; <alloc::sync::Arc<T,A> as core::clone::Clone>::clone
; Function Attrs: inlinehint uwtable
declare ptr @"_ZN68_$LT$alloc..sync..Arc$LT$T$C$A$GT$$u20$as$u20$core..clone..Clone$GT$5clone17h6b0f8d1ceb08b6bcE"(ptr align 8) unnamed_addr #0

; <&str as reqwest::into_url::IntoUrlSealed>::into_url
; Function Attrs: uwtable
declare void @"_ZN60_$LT$$RF$str$u20$as$u20$reqwest..into_url..IntoUrlSealed$GT$8into_url17hc31bf897d9923d7dE"(ptr sret([88 x i8]) align 8, ptr align 1, i64) unnamed_addr #1

; reqwest::async_impl::request::RequestBuilder::new
; Function Attrs: uwtable
declare void @_ZN7reqwest10async_impl7request14RequestBuilder3new17h2a35b4471788f9b6E(ptr sret([272 x i8]) align 8, ptr, ptr align 8) unnamed_addr #1

; core::ptr::drop_in_place<core::result::Result<reqwest::async_impl::request::Request,reqwest::error::Error>>
; Function Attrs: uwtable
declare void @"_ZN4core3ptr110drop_in_place$LT$core..result..Result$LT$reqwest..async_impl..request..Request$C$reqwest..error..Error$GT$$GT$17h31bb0087a3113920E"(ptr align 8) unnamed_addr #1

; core::ptr::drop_in_place<core::option::Option<reqwest::async_impl::body::Body>>
; Function Attrs: uwtable
declare void @"_ZN4core3ptr80drop_in_place$LT$core..option..Option$LT$reqwest..async_impl..body..Body$GT$$GT$17hb4c33df2e2e10187E"(ptr align 8) unnamed_addr #1

; core::ptr::drop_in_place<http::header::map::HeaderMap>
; Function Attrs: uwtable
declare void @"_ZN4core3ptr49drop_in_place$LT$http..header..map..HeaderMap$GT$17h761f53362e975f18E"(ptr align 8) unnamed_addr #1

; core::ptr::drop_in_place<url::Url>
; Function Attrs: uwtable
declare void @"_ZN4core3ptr29drop_in_place$LT$url..Url$GT$17h4960efdc1279e5aeE"(ptr align 8) unnamed_addr #1

; reqwest::blocking::request::RequestBuilder::new
; Function Attrs: uwtable
declare void @_ZN7reqwest8blocking7request14RequestBuilder3new17h760a82a405d52f5dE(ptr sret([328 x i8]) align 8, ptr align 8, ptr align 8) unnamed_addr #1

; core::ptr::drop_in_place<core::result::Result<reqwest::blocking::request::Request,reqwest::error::Error>>
; Function Attrs: uwtable
declare void @"_ZN4core3ptr108drop_in_place$LT$core..result..Result$LT$reqwest..blocking..request..Request$C$reqwest..error..Error$GT$$GT$17h46888f0e9084fff1E"(ptr align 8) unnamed_addr #1

; core::ptr::drop_in_place<core::option::Option<reqwest::blocking::body::Body>>
; Function Attrs: uwtable
declare void @"_ZN4core3ptr78drop_in_place$LT$core..option..Option$LT$reqwest..blocking..body..Body$GT$$GT$17hc05a19dc7ee303acE"(ptr align 8) unnamed_addr #1

; reqwest::async_impl::client::Client::new
; Function Attrs: uwtable
declare ptr @_ZN7reqwest10async_impl6client6Client3new17h002af87b15b4de93E() unnamed_addr #1

; reqwest::async_impl::request::RequestBuilder::send
; Function Attrs: uwtable
declare { i64, ptr } @_ZN7reqwest10async_impl7request14RequestBuilder4send17hca2adc12c5834e3aE(ptr align 8) unnamed_addr #1

; core::panicking::panic_const::panic_const_async_fn_resumed
; Function Attrs: cold noinline noreturn uwtable
declare void @_ZN4core9panicking11panic_const28panic_const_async_fn_resumed17h009012cf7da8298dE(ptr align 8) unnamed_addr #4

; core::panicking::panic_const::panic_const_async_fn_resumed_panic
; Function Attrs: cold noinline noreturn uwtable
declare void @_ZN4core9panicking11panic_const34panic_const_async_fn_resumed_panic17h0dd5db8d3c6f4651E(ptr align 8) unnamed_addr #4

; <reqwest::async_impl::client::Pending as core::future::future::Future>::poll
; Function Attrs: uwtable
declare void @"_ZN85_$LT$reqwest..async_impl..client..Pending$u20$as$u20$core..future..future..Future$GT$4poll17h3b880a10240d43cfE"(ptr sret([136 x i8]) align 8, ptr align 8, ptr align 8) unnamed_addr #1

; core::ptr::drop_in_place<core::result::Result<reqwest::async_impl::response::Response,reqwest::error::Error>>
; Function Attrs: uwtable
declare void @"_ZN4core3ptr112drop_in_place$LT$core..result..Result$LT$reqwest..async_impl..response..Response$C$reqwest..error..Error$GT$$GT$17h736911f91e59a316E"(ptr align 8) unnamed_addr #1

; reqwest::blocking::client::Client::new
; Function Attrs: uwtable
declare void @_ZN7reqwest8blocking6client6Client3new17h5040d938b90bba96E(ptr sret([24 x i8]) align 8) unnamed_addr #1

; reqwest::blocking::request::RequestBuilder::send
; Function Attrs: uwtable
declare void @_ZN7reqwest8blocking7request14RequestBuilder4send17h321b79deb49694bfE(ptr sret([176 x i8]) align 8, ptr align 8) unnamed_addr #1

; core::ptr::drop_in_place<reqwest::blocking::client::Client>
; Function Attrs: uwtable
declare void @"_ZN4core3ptr54drop_in_place$LT$reqwest..blocking..client..Client$GT$17h52a2f1acad4939c9E"(ptr align 8) unnamed_addr #1

attributes #0 = { inlinehint uwtable "target-cpu"="x86-64" "target-features"="+cx16,+sse3,+sahf" }
attributes #1 = { uwtable "target-cpu"="x86-64" "target-features"="+cx16,+sse3,+sahf" }
attributes #2 = { "target-cpu"="x86-64" }
attributes #3 = { nocallback nofree nounwind willreturn memory(argmem: readwrite) }
attributes #4 = { cold noinline noreturn uwtable "target-cpu"="x86-64" "target-features"="+cx16,+sse3,+sahf" }
attributes #5 = { cold }
attributes #6 = { noreturn }

!llvm.module.flags = !{!0}
!llvm.ident = !{!1}

!0 = !{i32 8, !"PIC Level", i32 2}
!1 = !{!"rustc version 1.86.0 (05f9846f8 2025-03-31)"}
