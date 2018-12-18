import csv
import tensorflow as tf
import random

import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'

"""
ValidLabels = ['AdWare', 'Backdoor', 'Downloader', 'Hoax', 'Net-Worm', 'Packed', 'Trojan', 'Trojan-Downloader',
                   'Trojan-Dropper', 'Trojan-FakeAV', 'Trojan-GameThief', 'Trojan-PSW', 'Trojan-Ransom', 'Trojan-Spy',
                   'Virus', 'WebToolbar', 'Worm']
"""
ValidLabels = ['AdWare', 'Packed', 'Trojan', 'Trojan-FakeAV']   # 사용할 악성코드 레이블을 지정

ApiToSymbolList = dict()
LabelToIdx = dict()
temp_idx = 0
for valid_label in ValidLabels:
    LabelToIdx[valid_label] = temp_idx
    temp_idx += 1
HashDictionary = dict()
TrainData = list()
TrainLabel = list()
TrainSeqLen = list()
TestData = list()
TestLabel = list()
TestSeqLen = list()
Batch_Pointer = 0
Max_Seq_Len = -1

# 값을 변경시킬 만한 변수들 (RNN 학습에 사용됨)
EPOCH = 15              # 학습 세대 (generation)
BATCH_SIZE = 256        # 한번에 학습시키는 데이터 수 (batch)
TRAINING_STEPS = 100    # 한 세대(generation)에 학습시키는 횟수
NUM_HIDDEN_LAYERS = 20  # RNN 히든 레이어 갯수


# 악성코드 레이블을 추출하는 함수
def _refine_label(label_name):
    if label_name == '':
        return 'no_label'

    splitted_name = label_name.split(':')
    if len(splitted_name) == 1:
        splitted_name = splitted_name[0]
    elif len(splitted_name) == 2:
        splitted_name = splitted_name[1]
    elif len(splitted_name) == 3:
        splitted_name = splitted_name[2]
    else:
        print(label_name)
        raise NotImplementedError

    splitted_detail = splitted_name.split('.')
    return splitted_detail[0]


# 데이터셋을 로드하는 함수
def _load_dataset():
    global Max_Seq_Len

    temp_max = -1
    with open('new_malware_API_dataset.csv', 'rt') as dataset_file:
        csv_reader = csv.DictReader(dataset_file, fieldnames=['index', 'hash', 'label', 'api_seq'])
        for line in csv_reader:
            mal_label = _refine_label(line['label'])
            if mal_label not in ValidLabels:
                continue

            mal_idx = line['index']
            mal_api_seq = line['api_seq']
            if temp_max < len(mal_api_seq):
                temp_max = len(mal_api_seq)
            if mal_label not in HashDictionary:
                HashDictionary[mal_label] = list()
            HashDictionary[mal_label].append({'idx': mal_idx, 'api_seq': mal_api_seq})
    Max_Seq_Len = temp_max


# 문자열을 숫자열로 인코딩하는 함수
def _convert_char_to_encoding(api_seq):
    result_encoded_seq = list()

    for api in api_seq:
        if api == '0':
            encoded = [float(0)]
        else:
            encoded = [float(ord(api) - ord('A') + 1)]
        result_encoded_seq.append(encoded)

    return result_encoded_seq


# 문자열의 길이를 일정하게 맞추고(패딩) 숫자열로 인코딩하는 함수
def _encode_data(api_seq):
    aligned_api_seq = list(api_seq).copy()
    sequence_length = len(aligned_api_seq)

    padding_size = Max_Seq_Len - sequence_length
    if padding_size > 0:
        padding = ['0' for _ in range(padding_size)]
        aligned_api_seq += padding
    converted_api_seq = _convert_char_to_encoding(aligned_api_seq)

    return converted_api_seq, sequence_length


# 데이터셋을 training 데이터셋과 testing 데이터셋으로 나누는 함수
def _split_dataset():
    de_sum = 0
    default_label = [0 for _ in range(len(ValidLabels))]
    for label in HashDictionary.keys():
        num_hashes = len(HashDictionary[label])
        print('The number of <%s>: %d' % (label, num_hashes))
        de_sum += num_hashes

        rand_test_idx_list = random.sample(range(0, num_hashes), int(num_hashes/10))
        for idx in range(num_hashes):
            encoded_api_seq, sequence_length = _encode_data(HashDictionary[label][idx]['api_seq'])

            one_hot_label = default_label.copy()
            one_hot_label[LabelToIdx[label]] = 1

            if idx in rand_test_idx_list:
                TestData.append(encoded_api_seq)
                TestLabel.append(one_hot_label)
                TestSeqLen.append(sequence_length)
            else:
                TrainData.append(encoded_api_seq)
                TrainLabel.append(one_hot_label)
                TrainSeqLen.append(sequence_length)

    print('The number of hashes: %d' % de_sum)
    print('The number of train: %d' % len(TrainData))
    print('The number of test: %d' % len(TestData))


# RNN에 사용할 데이터셋을 로드하는 함수
def setup():
    _load_dataset()     # .csv 파일로부터 데이터셋을 로드
    _split_dataset()    # 데이터셋을 Train 데이터셋과 Test 데이터셋으로 분할


# Training 데이터셋으로부터 데이터 한 묶음(batch)을 가져오는 함수
def _get_next_batch(batch_size):
    global Batch_Pointer

    train_data_size = len(TrainData)
    if Batch_Pointer + batch_size >= train_data_size:
        result_x = TrainData[Batch_Pointer:]
        result_y = TrainLabel[Batch_Pointer:]
        result_seq_len = TrainSeqLen[Batch_Pointer:]
        rest = Batch_Pointer + batch_size - train_data_size

        while True:
            if rest < train_data_size:
                Batch_Pointer = rest
                if Batch_Pointer > 0:
                    result_x += TrainData[0:Batch_Pointer-1]
                    result_y += TrainLabel[0:Batch_Pointer-1]
                    result_seq_len += TrainSeqLen[0:Batch_Pointer-1]
                break
            else:
                result_x += TrainData
                result_y += TrainLabel
                result_seq_len += TrainSeqLen
                rest -= train_data_size

    else:
        result_x = TrainData[Batch_Pointer: Batch_Pointer+batch_size]
        result_y = TrainLabel[Batch_Pointer: Batch_Pointer+batch_size]
        result_seq_len = TrainSeqLen[Batch_Pointer: Batch_Pointer+batch_size]
        Batch_Pointer += batch_size

    return result_x, result_y, result_seq_len


# RNN을 텐서플로우로 구현 및 training과 testing을 하는 함수
def run_rnn():
    input_dim = 1                   # 입력 데이터의 차원
    seq_max_len = Max_Seq_Len       # API 시퀀스의 최대 길이
    num_classes = len(ValidLabels)  # 클래스 갯수 (레이블 갯수)

    learning_rate = 0.001
    steps = TRAINING_STEPS          # 한 세대에 학습시키는 횟수
    batch_size = BATCH_SIZE         # 한번에 학습시키는 데이터 수 (batch)
    n_hidden = NUM_HIDDEN_LAYERS    # 히든 레이어 갯수

    x = tf.placeholder(tf.float32, [None, seq_max_len, input_dim])  # 입력 시퀀스 홀더
    seq_len = tf.placeholder(tf.int32, [None])                      # 시퀀스 길이 홀더
    y = tf.placeholder(tf.float32, [None, num_classes])             # 출력 레이블 홀더

    weights = tf.Variable(tf.random_normal([n_hidden, num_classes]))    # W
    biases = tf.Variable(tf.random_normal([num_classes]))   # b

    lstm_cell = tf.nn.rnn_cell.LSTMCell(num_units=n_hidden, forget_bias=1.0)    # LSTM 셀 생성
    outputs, states = tf.nn.dynamic_rnn(lstm_cell, x, sequence_length=seq_len, dtype=tf.float32)    # LSTM 셀로 RNN을 생성함

    idx = tf.range(0, tf.shape(outputs)[0]) * seq_max_len + (seq_len - 1)
    outputs = tf.gather(tf.reshape(outputs, [-1, n_hidden]), idx)   # X
    hypothesis = tf.matmul(outputs, weights) + biases   # WX + b
    cost = tf.reduce_mean(tf.square(hypothesis - y))    # Cost(loss) 함수

    optimizer = tf.train.AdamOptimizer(learning_rate=learning_rate).minimize(cost)  # Cost(loss)가 최소가 되는 지점을 찾는 함수

    with tf.Session() as sess:
        sess.run(tf.global_variables_initializer())

        # RNN Training 부분
        for epoch in range(EPOCH):  # 학습 세대 (generation)
            avg_cost = 0

            for batch_idx in range(steps):  # 세대당 학습 횟수
                batch_x, batch_y, batch_seq_len = _get_next_batch(batch_size)
                feed_dict = {x: batch_x, y: batch_y, seq_len: batch_seq_len}

                loss, _ = sess.run([cost, optimizer], feed_dict=feed_dict)
                avg_cost += loss / steps
            print('Epoch:', '%04d' % (epoch + 1), 'cost =', '{:.9f}'.format(avg_cost))
        print("Learning Finished!")

        # RNN Testing 부분
        correct_prediction = tf.equal(tf.argmax(hypothesis, 1), tf.argmax(y, 1))
        accuracy = tf.reduce_mean(tf.cast(correct_prediction, tf.float32))
        print("Testing Accuracy:", sess.run(accuracy, feed_dict={x: TestData, y: TestLabel, seq_len: TestSeqLen}))


if __name__ == "__main__":
    setup()
    run_rnn()
