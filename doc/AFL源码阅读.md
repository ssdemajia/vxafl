---
title: AFL源码阅读
date: 2020-02-12 21:59:18
tags:afl

---

AFL是基于覆盖率指导变异的模糊测试方法，相对于符号执行的缓慢，AFL在实际应用中很有效，因此我十分好奇它的原理：

- 如何获得代码覆盖率

- 如何对测试用例进行变异(变异策略)

- 如何筛选测试用例

- 如何统计测试信息

## 项目结构

- afl-analyze.c 分析测试程序所使用的文件格式
- afl-cmin.c 减少大规模预料库中冗余的预料文件
- afl-tmin.c 减少触发相同执行路径的测试用例

## 运行测试用例

在每次测试用例修改过，afl都会调用`common_fuzz_stuff`函数来运行测试程序。

```c
EXP_ST u8 common_fuzz_stuff(char** argv, u8* out_buf, u32 len) {
  u8 fault;
  write_to_testcase(out_buf, len); // 将修改过的测试用例写入文件中
    /*运行目标程序*/
  fault = run_target(argv, exec_tmout); 
	
  if (stop_soon) return 1;
  if (fault == FAULT_TMOUT) { // 出现超时错误
    if (subseq_tmouts++ > TMOUT_LIMIT) {
      cur_skipped_paths++; // cur_skipped_paths统计废弃的测试用例数量
      return 1;
    }
  } else subseq_tmouts = 0;

  /* 用户触发SIGUSR1信号表示跳过当前测试用例 */
  if (skip_requested) {
     skip_requested = 0;
     cur_skipped_paths++;
     return 1;

  }
  // 处理返回错误的情况
  queued_discovered += save_if_interesting(argv, out_buf, len, fault);

  if (!(stage_cur % stats_update_freq) || stage_cur + 1 == stage_max)
    show_stats();

  return 0;

}
```

在run_target函数中，afl会对trace_bits进行清零操作。

1. 如果forkserver还没启动，就fork一个子进程运行测试程序中
2. 如果已经建立forkserver，那么父进程与子进程的fork_server进行通信（交流子进程pid什么的）
3. 之后设置定时器，并等待forkserver将子进程运行结果（status）传回。
4. `classify_counts`将trace_bits的边edge转化为类计数。
5. 然后将status分类，包括CRASH、TIMEOUT、ERROR、NONE等。

```c
static u8 run_target(char** argv, u32 timeout) {

  static struct itimerval it;
  static u32 prev_timed_out = 0;
  static u64 exec_ms = 0;

  int status = 0;
  u32 tb4;
  memset(trace_bits, 0, MAP_SIZE); // 清空trace_bits
  if (dumb_mode == 1 || no_forkserver) {
    child_pid = fork();
    if (!child_pid) { // 子进程
      execv(target_path, argv);
      PFATAL("error:%s\n", strerror(errno));
      *(u32*)trace_bits = EXEC_FAIL_SIG;
      exit(0);
    }

  } else {
    s32 res;
    // 已经有了forkserver了
    // 向forkserver通讯
    write(fsrv_ctl_fd, &prev_timed_out, 4)
    read(fsrv_st_fd, &child_pid, 4)) != 4)
  }
   // 设置计时器
   it.it_value.tv_sec = (timeout / 1000);
   it.it_value.tv_usec = (timeout % 1000) * 1000;
   setitimer(ITIMER_REAL, &it, NULL);

   // 获得子进程状态
	res = read(fsrv_st_fd, &status, 4);

  }


  getitimer(ITIMER_REAL, &it);
  /* 执行时间 */
  exec_ms = (u64) timeout - (it.it_value.tv_sec * 1000 +
                             it.it_value.tv_usec / 1000);
  tb4 = *(u32*)trace_bits;
// 将trace_bits进行计数分类
#ifdef __x86_64__
  classify_counts((u64*)trace_bits);
#else
  classify_counts((u32*)trace_bits);

 对status进行分类

}
```

在一个用例运行结束后，afl会调用`save_if_interesting`来判断是否将当前测试用例放入队列中。在这个函数中会保存Crash和Hang的测试用例。

```c
static u8 save_if_interesting(char** argv, void* mem, u32 len, u8 fault) {

  u8  *fn = "";
  u8  hnb;
  s32 fd;
  u8  keeping = 0, res;

  switch (fault) {
    case FAULT_TMOUT: // 超时错误
      total_tmouts++;

      if (unique_hangs >= KEEP_UNIQUE_HANG) return keeping;

      if (!dumb_mode) {
        simplify_trace((u64*)trace_bits);
        if (!has_new_bits(virgin_tmout)) return keeping; // 超时的测试用例需要比virgin_tmout有新的边
      }

      unique_tmouts++;
       if (exec_tmout < hang_tmout) {

        u8 new_fault;
        write_to_testcase(mem, len);
        new_fault = run_target(argv, hang_tmout);

        if (!stop_soon && new_fault == FAULT_CRASH) goto keep_as_crash;

        if (stop_soon || new_fault != FAULT_TMOUT) return keeping;

      }
      fn = alloc_printf("%s/hangs/id_%06llu", out_dir,
                        unique_hangs);
      unique_hangs++;

      last_hang_time = get_cur_time();

      break;

    case FAULT_CRASH: // 崩溃错误

keep_as_crash:
      total_crashes++;

      if (unique_crashes >= KEEP_UNIQUE_CRASH) return keeping;

      if (!dumb_mode) {
        simplify_trace((u64*)trace_bits);
        if (!has_new_bits(virgin_crash)) return keeping;
      }

      if (!unique_crashes) write_crash_readme();
      fn = alloc_printf("%s/crashes/id:%06llu,sig:%02u,%s", out_dir,
                        unique_crashes, kill_signal, describe_op(0));
      unique_crashes++;

      last_crash_time = get_cur_time();
      last_crash_execs = total_execs;

      break;
    case FAULT_ERROR: FATAL("Unable to execute target application");
    default: return keeping;
  }
  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) PFATAL("Unable to create '%s'", fn);
  ck_write(fd, mem, len, fn);
  close(fd);

  ck_free(fn);
  return keeping;
}
```

在每次测试队列循环中，首先会对队列中的测试用例进行剔除，这个剔除操作是cull_queue完成

```c
static void cull_queue(void) {
  struct queue_entry* q;
  static u8 temp_v[MAP_SIZE >> 3];
  u32 i;

  if (dumb_mode || !score_changed) return;

  score_changed = 0;
  memset(temp_v, 255, MAP_SIZE >> 3);

  queued_favored  = 0;
  pending_favored = 0;

  q = queue;

  while (q) {
    q->favored = 0;
    q = q->next;
  }

  /* Let's see if anything in the bitmap isn't captured in temp_v.
     If yes, and if it has a top_rated[] contender, let's use it. */

  for (i = 0; i < MAP_SIZE; i++)
    if (top_rated[i] && (temp_v[i >> 3] & (1 << (i & 7)))) {

      u32 j = MAP_SIZE >> 3;

      /* Remove all bits belonging to the current entry from temp_v. */

      while (j--) 
        if (top_rated[i]->trace_mini[j])
          temp_v[j] &= ~top_rated[i]->trace_mini[j];

      top_rated[i]->favored = 1;
      queued_favored++;

      if (!top_rated[i]->was_fuzzed) pending_favored++;

    }

  q = queue;

  while (q) {
    mark_as_redundant(q, !q->favored);
    q = q->next;
  }

}
```



## 变异策略

## 输出

测试过程中会产生三个文件夹分别是：

1. queue/ ：每个独立执行路径对应的测试用例队列，也包括用户提供的初始测试用例。
2. crashes/ ：引起程序触发致命错误的测试用例。
3. hangs/ ：引起测试程序超时的测试用例。

## afl-analyze.c

## afl-tmin.c

## afl-cmin.c

## 参考

1. afl-analyze介绍，https://lcamtuf.blogspot.com/2016/02/say-hello-to-afl-analyze.html
2. afl流程解析 http://rk700.github.io/2017/12/28/afl-internals/
3. afl变异算法解析http://rk700.github.io/2018/02/02/afl-enhancement/
4. afl源码阅读 https://bbs.pediy.com/thread-254705.htm
5. afl项目分析https://bbs.pediy.com/thread-249912.htm