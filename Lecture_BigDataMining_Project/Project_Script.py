

HashDictionary = list()
UniqueAPIs = set()
UniqueLabels = set()
LabelStat = dict()


def refine_label(label_name):
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


def setup():
    dataset_file = open('malware_API_dataset.csv', 'rt')

    while True:
        line = dataset_file.readline()
        if not line:
            break

        new_dict = dict()
        splitted_line = line.split('","')
        if splitted_line[1] not in HashDictionary:
            new_dict['hash'] = splitted_line[1]
        else:
            raise Exception

        refined_label = refine_label(splitted_line[0][1:])

        if refined_label not in LabelStat:
            LabelStat[refined_label] = 0
        LabelStat[refined_label] += 1
        UniqueLabels.add(refined_label)
        new_dict['label'] = refined_label
        new_dict['api_seq'] = list()
        for idx in range(len(splitted_line)):
            if idx in [0, 1]:
                continue

            if splitted_line[idx] == splitted_line[-1]:
                new_api = splitted_line[idx][:-2]
            else:
                new_api = splitted_line[idx]
            UniqueAPIs.add(new_api)
            new_dict['api_seq'].append(new_api)

        # print(new_dict['hash'])
        # print(new_dict['label'])
        # print(new_dict['api_seq'])
        HashDictionary.append(new_dict)

    dataset_file.close()


setup()
print('Num of unique Hashes: %d' % len(HashDictionary))
print('Num of unique APIs: %d' % len(UniqueAPIs))
print('Num of unique Labels: %d' % len(UniqueLabels))
for label in LabelStat.keys():
    print(label)
    print(LabelStat[label])
    print()
