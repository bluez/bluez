/*
 * Copyright (C) 2007 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _CUTILS_LOG_H
#define _CUTILS_LOG_H

#define ALOGV(...)
#define ALOGD(...)
#define ALOGI(...)
#define ALOGW(...)
#define ALOGE(...)
#define LOG_ALWAYS_FATAL(...)   do { ALOGE(__VA_ARGS__); exit(1); } while (0)

#endif // _CUTILS_LOG_H
