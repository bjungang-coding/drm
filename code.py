import os
import time
import numpy as np
import matplotlib.pyplot as plt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# -------------------------------
# 실험 1: AES vs. HC-256 (모의) 암호화 비교
# -------------------------------

def encrypt_aes(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = pad(data, AES.block_size)
    start = time.time()
    ciphertext = cipher.encrypt(padded_data)
    end = time.time()
    return ciphertext, end - start

def decrypt_aes(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    start = time.time()
    padded_plain = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plain, AES.block_size)
    end = time.time()
    return plaintext, end - start

def encrypt_hc256_sim(data, key):
    # HC-256 모의 구현: 단순 XOR 암호화 (실제 HC-256과는 다름)
    # 키를 반복하여 데이터를 XOR
    key_len = len(key)
    start = time.time()
    ciphertext = bytearray(len(data))
    for i in range(len(data)):
        ciphertext[i] = data[i] ^ key[i % key_len]
    end = time.time()
    return bytes(ciphertext), end - start

def decrypt_hc256_sim(ciphertext, key):
    key_len = len(key)
    start = time.time()
    plaintext = bytearray(len(ciphertext))
    for i in range(len(ciphertext)):
        plaintext[i] = ciphertext[i] ^ key[i % key_len]
    end = time.time()
    return bytes(plaintext), end - start

def experiment1():
    iterations = 10
    data_size = 5 * 1024 * 1024  # 5MB 데이터
    aes_decrypt_times = []
    hc256_decrypt_times = []
  
    aes_key = os.urandom(16)
    hc256_key = os.urandom(16)
    
    print("실험 1: AES vs. HC-256 (모의) 복호화 시간 비교")
    for i in range(iterations):
        data = os.urandom(data_size)
        # AES 암호화 및 복호화
        aes_ciphertext, enc_time_aes = encrypt_aes(data, aes_key)
        _, dec_time_aes = decrypt_aes(aes_ciphertext, aes_key)
        aes_decrypt_times.append(dec_time_aes * 1000)  # ms 단위
        
        # HC-256 (모의) 암호화 및 복호화
        hc256_ciphertext, enc_time_hc256 = encrypt_hc256_sim(data, hc256_key)
        _, dec_time_hc256 = decrypt_hc256_sim(hc256_ciphertext, hc256_key)
        hc256_decrypt_times.append(dec_time_hc256 * 1000)  # ms 단위
        
        print(f"반복 {i+1}: AES 복호화 시간 = {dec_time_aes*1000:.2f} ms, HC-256 모의 복호화 시간 = {dec_time_hc256*1000:.2f} ms")
    
    iters = np.arange(1, iterations+1)
    plt.figure(figsize=(6,4))
    plt.plot(iters, aes_decrypt_times, marker='o', label='AES 복호화 시간')
    plt.plot(iters, hc256_decrypt_times, marker='s', label='HC-256 (모의) 복호화 시간')
    plt.xlabel('반복 횟수')
    plt.ylabel('복호화 시간 (ms)')
    plt.title('AES vs. HC-256 복호화 시간 비교')
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.show()

# -------------------------------
# 실험 2: 모바일 DRM - 전체 암호화 vs. 부분암호화 비교
# -------------------------------

def full_encryption(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = pad(data, AES.block_size)
    start = time.time()
    ciphertext = cipher.encrypt(padded_data)
    end = time.time()
    return ciphertext, end - start

def partial_encryption(data, key, segment_ratio=0.5):
    segment_size = 1024 * 1024  # 1MB 단위
    num_segments = len(data) // segment_size
    segments = [data[i*segment_size:(i+1)*segment_size] for i in range(num_segments)]
    if len(data) % segment_size:
        segments.append(data[num_segments*segment_size:])
    
    cipher = AES.new(key, AES.MODE_ECB)
    total_time = 0
    encrypted_segments = []
    for seg in segments:
        if np.random.rand() < segment_ratio:
            padded_seg = pad(seg, AES.block_size)
            start = time.time()
            enc_seg = cipher.encrypt(padded_seg)
            end = time.time()
            total_time += (end - start)
            encrypted_segments.append(enc_seg)
        else:
            encrypted_segments.append(seg)
    return encrypted_segments, total_time

def experiment2():
    content_sizes = [5, 10, 15, 20]  # MB 단위
    full_times = []
    partial_times = []
    aes_key = os.urandom(16)
    
    print("실험 2: 전체 암호화 vs. 부분암호화 시간 비교 (모바일 DRM)")
    for size in content_sizes:
        data = os.urandom(size * 1024 * 1024)
        _, t_full = full_encryption(data, aes_key)
        _, t_partial = partial_encryption(data, aes_key, segment_ratio=0.5)
        full_times.append(t_full * 1000)    # ms 단위
        partial_times.append(t_partial * 1000)
        print(f"{size}MB: 전체 암호화 = {t_full*1000:.2f} ms, 부분암호화 = {t_partial*1000:.2f} ms")
    
    # 에너지 소비(시간)를 비교하는 그래프
    plt.figure(figsize=(10,4))
    plt.subplot(1,2,1)
    plt.plot(content_sizes, full_times, marker='o', label='전체 암호화')
    plt.plot(content_sizes, partial_times, marker='s', label='부분암호화')
    plt.xlabel('콘텐츠 용량 (MB)')
    plt.ylabel('암호화 시간 (ms)')
    plt.title('전체 암호화 vs. 부분암호화 - 시간 비교')
    plt.legend()
    plt.grid(True)
    
    # 시간 대비 절감 비율 그래프
    reduction = (np.array(full_times) - np.array(partial_times)) / np.array(full_times) * 100
    plt.subplot(1,2,2)
    plt.bar(content_sizes, reduction, color='coral')
    plt.xlabel('콘텐츠 용량 (MB)')
    plt.ylabel('시간 절감율 (%)')
    plt.title('부분암호화 시간 절감율')
    plt.grid(True)
    
    plt.tight_layout()
    plt.show()

# -------------------------------
# 실험 3: GStreamer 기반 DRM 시스템 상호 운용성 시뮬레이션
# -------------------------------

def simulate_streaming(environment, num_sessions=100):
    if environment == '유선':
        mean_delay, std_delay = 120, 10
    elif environment == '무선':
        mean_delay, std_delay = 140, 20
    elif environment == '혼합':
        mean_delay, std_delay = 130, 15
    else:
        mean_delay, std_delay = 150, 20
        
    delays = np.random.normal(mean_delay, std_delay, num_sessions)
    # 오류율: 재생 지연이 160ms 이상이면 오류 발생으로 간주
    errors = np.sum(delays > 160)
    error_rate = errors / num_sessions * 100
    avg_delay = np.mean(delays)
    return avg_delay, error_rate

def experiment3():
    environments = ['유선', '무선', '혼합']
    avg_delays = []
    error_rates = []
    
    print("실험 3: GStreamer 기반 DRM 시스템 상호 운용성 평가 시뮬레이션")
    for env in environments:
        avg_delay, error_rate = simulate_streaming(env)
        avg_delays.append(avg_delay)
        error_rates.append(error_rate)
        print(f"{env}: 평균 재생 지연 = {avg_delay:.2f} ms, 오류율 = {error_rate:.2f}%")
    
    # 재생 지연 그래프 (막대 그래프)
    plt.figure(figsize=(10,4))
    plt.subplot(1,2,1)
    plt.bar(environments, avg_delays, color='skyblue')
    plt.xlabel('테스트 환경')
    plt.ylabel('평균 재생 지연 (ms)')
    plt.title('GStreamer DRM: 재생 지연')
    plt.grid(True)
    
    # 오류율 그래프 (막대 그래프)
    plt.subplot(1,2,2)
    plt.bar(environments, error_rates, color='lightgreen')
    plt.xlabel('테스트 환경')
    plt.ylabel('오류율 (%)')
    plt.title('GStreamer DRM: 오류율')
    plt.grid(True)
    
    plt.tight_layout()
    plt.show()

# -------------------------------
# 메인 실행 부분
# -------------------------------

if __name__ == "__main__":
    print("DRM 기술 실험 진행 중...")
    experiment1()  # AES vs. HC-256 암호화 비교
    experiment2()  # 전체 암호화 vs. 부분암호화 비교 (모바일 DRM)
    experiment3()  # GStreamer 기반 DRM 시스템 시뮬레이션
