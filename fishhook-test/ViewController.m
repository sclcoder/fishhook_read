//
//  ViewController.m
//  fishhook-test
//
//  Created by 孙春磊 on 2020/3/24.
//  Copyright © 2020 coder. All rights reserved.
//

#import "ViewController.h"
#import "fishhook/fishhook.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    NSLog(@"NSLog符号还没被绑定");
    
    NSLog(@"NSLog被绑定了");
    

    struct rebinding nslog;
    nslog.name = "NSLog";
    nslog.replacement = mylog;
    nslog.replaced = (void *)&syslog;
    
    /// rebinding结构体数组
    struct rebinding rebs[1] = {nslog};
    /// 重绑定
    rebind_symbols(rebs, 1);
}

/************** 更改NSLog*************/

/// 函数指针：用于接收NSLog函数地址
static void(* syslog)(NSString *format, ...);
/// 替换NSLog的函数
void mylog(NSString *format, ...){
    format = [format stringByAppendingFormat:@"hook到了!\n"];
    /// 调用原来实现
    syslog(format);
}



- (void)touchesBegan:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event{
    NSLog(@"NSLog被hook了");
}


@end
