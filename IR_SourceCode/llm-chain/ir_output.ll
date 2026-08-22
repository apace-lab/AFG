; ModuleID = '0gr3b7ohje2li8pljnqu5h576'
source_filename = "0gr3b7ohje2li8pljnqu5h576"
target datalayout = "e-m:w-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-windows-msvc"

@alloc_58a5ca2f6c0a009ba8ef0dc9c20632a7 = private unnamed_addr constant <{ [99 x i8] }> <{ [99 x i8] c"C:\\Users\\hanna\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f\\llm-chain-0.13.0\\src\\options.rs" }>, align 1
@alloc_4fe8747a0f3690f123d99565f5865404 = private unnamed_addr constant <{ ptr, [16 x i8] }> <{ ptr @alloc_58a5ca2f6c0a009ba8ef0dc9c20632a7, [16 x i8] c"c\00\00\00\00\00\00\00\0B\00\00\00\1A\00\00\00" }>, align 8

; <llm_chain::options::Options as core::clone::Clone>::clone
; Function Attrs: inlinehint uwtable
define internal void @"_ZN66_$LT$llm_chain..options..Options$u20$as$u20$core..clone..Clone$GT$5clone17h69ecd9e81a82fc69E"(ptr sret([24 x i8]) align 8 %_0, ptr align 8 %self) unnamed_addr #0 {
start:
  %_2 = alloca [24 x i8], align 8
; call <alloc::vec::Vec<T,A> as core::clone::Clone>::clone
  call void @"_ZN67_$LT$alloc..vec..Vec$LT$T$C$A$GT$$u20$as$u20$core..clone..Clone$GT$5clone17hbf0777b4a8c865fdE"(ptr sret([24 x i8]) align 8 %_2, ptr align 8 %self, ptr align 8 @alloc_4fe8747a0f3690f123d99565f5865404)
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %_0, ptr align 8 %_2, i64 24, i1 false)
  ret void
}

; llm_chain::chains::sequential::Chain::run
; Function Attrs: uwtable
define void @_ZN9llm_chain6chains10sequential5Chain3run17h129a97adbd36bc86E(ptr sret([368 x i8]) align 8 %_0, ptr align 8 %self, ptr align 8 %parameters, ptr align 8 %executor) unnamed_addr #1 {
start:
  %0 = getelementptr inbounds i8, ptr %_0, i64 96
  store ptr %self, ptr %0, align 8
  %1 = getelementptr inbounds i8, ptr %_0, i64 32
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %1, ptr align 8 %parameters, i64 24, i1 false)
  %2 = getelementptr inbounds i8, ptr %_0, i64 104
  store ptr %executor, ptr %2, align 8
  %3 = getelementptr inbounds i8, ptr %_0, i64 113
  store i8 0, ptr %3, align 1
  ret void
}

; llm_chain::traits::Executor::new
; Function Attrs: uwtable
define void @_ZN9llm_chain6traits8Executor3new17h3e2ed1337da6d5ccE(ptr sret([32 x i8]) align 8 %_0) unnamed_addr #1 {
start:
  %_1 = alloca [24 x i8], align 8
; call llm_chain::options::Options::empty
  %_2 = call align 8 ptr @_ZN9llm_chain7options7Options5empty17h9477d801041c2946E()
; call <llm_chain::options::Options as core::clone::Clone>::clone
  call void @"_ZN66_$LT$llm_chain..options..Options$u20$as$u20$core..clone..Clone$GT$5clone17h69ecd9e81a82fc69E"(ptr sret([24 x i8]) align 8 %_1, ptr align 8 %_2)
; call <llm_chain_openai::chatgpt::executor::Executor as llm_chain::traits::Executor>::new_with_options
  call void @"_ZN93_$LT$llm_chain_openai..chatgpt..executor..Executor$u20$as$u20$llm_chain..traits..Executor$GT$16new_with_options17h77e6f9b7f57d3e6dE"(ptr sret([32 x i8]) align 8 %_0, ptr align 8 %_1)
  ret void
}

; llm_chain::call_execute
; Function Attrs: uwtable
define { ptr, ptr } @_ZN9llm_chain12call_execute17h36498b3ee0acd590E(ptr align 8 %exec, ptr align 8 %options, ptr align 8 %prompt) unnamed_addr #1 {
start:
; call <llm_chain_openai::chatgpt::executor::Executor as llm_chain::traits::Executor>::execute
  %0 = call { ptr, ptr } @"_ZN93_$LT$llm_chain_openai..chatgpt..executor..Executor$u20$as$u20$llm_chain..traits..Executor$GT$7execute17hb0249a65a36d00dcE"(ptr align 8 %exec, ptr align 8 %options, ptr align 8 %prompt)
  %_0.0 = extractvalue { ptr, ptr } %0, 0
  %_0.1 = extractvalue { ptr, ptr } %0, 1
  %1 = insertvalue { ptr, ptr } poison, ptr %_0.0, 0
  %2 = insertvalue { ptr, ptr } %1, ptr %_0.1, 1
  ret { ptr, ptr } %2
}

; llm_chain::call_chain_run
; Function Attrs: uwtable
define void @_ZN9llm_chain14call_chain_run17h2d4a092a8d3a214bE(ptr sret([368 x i8]) align 8 %_0, ptr align 8 %chain, ptr align 8 %parameters, ptr align 8 %executor) unnamed_addr #1 {
start:
; call llm_chain::chains::sequential::Chain::run
  call void @_ZN9llm_chain6chains10sequential5Chain3run17h129a97adbd36bc86E(ptr sret([368 x i8]) align 8 %_0, ptr align 8 %chain, ptr align 8 %parameters, ptr align 8 %executor)
  ret void
}

; llm_chain::make_executor
; Function Attrs: uwtable
define void @_ZN9llm_chain13make_executor17h8728baa39c7f2691E(ptr sret([32 x i8]) align 8 %_0) unnamed_addr #1 {
start:
; call llm_chain::traits::Executor::new
  call void @_ZN9llm_chain6traits8Executor3new17h3e2ed1337da6d5ccE(ptr sret([32 x i8]) align 8 %_0)
  ret void
}

; <alloc::vec::Vec<T,A> as core::clone::Clone>::clone
; Function Attrs: uwtable
declare void @"_ZN67_$LT$alloc..vec..Vec$LT$T$C$A$GT$$u20$as$u20$core..clone..Clone$GT$5clone17hbf0777b4a8c865fdE"(ptr sret([24 x i8]) align 8, ptr align 8, ptr align 8) unnamed_addr #1

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: readwrite)
declare void @llvm.memcpy.p0.p0.i64(ptr noalias nocapture writeonly, ptr noalias nocapture readonly, i64, i1 immarg) #2

; llm_chain::options::Options::empty
; Function Attrs: uwtable
declare align 8 ptr @_ZN9llm_chain7options7Options5empty17h9477d801041c2946E() unnamed_addr #1

; <llm_chain_openai::chatgpt::executor::Executor as llm_chain::traits::Executor>::new_with_options
; Function Attrs: uwtable
declare void @"_ZN93_$LT$llm_chain_openai..chatgpt..executor..Executor$u20$as$u20$llm_chain..traits..Executor$GT$16new_with_options17h77e6f9b7f57d3e6dE"(ptr sret([32 x i8]) align 8, ptr align 8) unnamed_addr #1

; <llm_chain_openai::chatgpt::executor::Executor as llm_chain::traits::Executor>::execute
; Function Attrs: uwtable
declare { ptr, ptr } @"_ZN93_$LT$llm_chain_openai..chatgpt..executor..Executor$u20$as$u20$llm_chain..traits..Executor$GT$7execute17hb0249a65a36d00dcE"(ptr align 8, ptr align 8, ptr align 8) unnamed_addr #1

attributes #0 = { inlinehint uwtable "target-cpu"="x86-64" "target-features"="+cx16,+sse3,+sahf" }
attributes #1 = { uwtable "target-cpu"="x86-64" "target-features"="+cx16,+sse3,+sahf" }
attributes #2 = { nocallback nofree nounwind willreturn memory(argmem: readwrite) }

!llvm.module.flags = !{!0}
!llvm.ident = !{!1}

!0 = !{i32 8, !"PIC Level", i32 2}
!1 = !{!"rustc version 1.86.0 (05f9846f8 2025-03-31)"}
