# 基于离散余弦变换（DCT）的图片水印嵌入与提取

## 一、DCT介绍
DCT是离散余弦变换，它用一系列不同频率的余弦波的加权和（系数）来表示原始信号，进行DCT变换，将会把信号的大多数能量集中于频域的一个小范围内，即低频。纹理信息一般集中在高频，而低频包含又较多平滑的信息，人眼对平滑区域的变化较中高频的纹理信息更敏感，选择中频系数嵌入是最合适的。  
### 1、DCT的优势
1)相比于DFT，DCT只使用实数的余弦函数作为基函数，而DFT使用复数（包含余弦和正弦分量）。因此DCT在计算上更高效，并且对于具有强相关性的实数信号，其能量集中特性通常比DFT更好。  
2)DCT能将原本在空间/时间上高度相关的信号样本，转换成在变换域中相关性很弱的系数，后续处理更有效。  
### 2、DCT的应用
DCT在图像和视频压缩，音频压缩，信号处理，数字水印等方面都有非常重要的应用

## 二、实验原理
### 1、水印嵌入
#### 1)初始化与参数设置
在DCT_Embed类的构造函数__init__中，获取待嵌入水印的图像和水印图像的尺寸信息，进行尺寸合法性校验，确保水印图像尺寸不大于背景图像尺寸按设定块大小划分后的尺寸。同时初始化一些关键参数，如分块大小block_size（默认值为8）、嵌入强度系数alpha，以及用于嵌入时区分水印值（0 或 1）的两个随机向量k1和k2。注意根据分块大小block_size的值，水印图片的尺寸为待嵌入水印的图像的1/block_size。
```python
    def __init__(self, background, watermark, block_size=8, alpha=30):
        b_h, b_w = background.shape[:2]
        w_h, w_w = watermark.shape[:2]  # Adjust to handle 2D watermark
        assert w_h <= b_h / block_size and w_w <= b_w / block_size, \
            "\r\n请确保您的的水印图像尺寸 不大于 背景图像尺寸的1/{:}\r\nbackground尺寸{:}\r\nwatermark尺寸{:}".format(
                block_size, background.shape, watermark.shape
            )
        # 保存参数
        self.block_size = block_size
        # 水印强度控制
        self.alpha = alpha
        # 随机的序列
        self.k1 = np.random.randn(block_size)
        self.k2 = np.random.randn(block_size)
```
#### 2)图像分块与DCT变换
将输入的背景图像按照设定的块大小（如 8×8）进行分块。对于划分好的每个块，使用cv2.dct函数进行离散余弦变换，将图像从空间域转换到频域，得到对应块的DCT系数矩阵，最终形成一个包含所有分块DCT系数的多维数组，用于后续嵌入水印操作。
```python
    # DCT分块处理
    def dct_blkproc(self, background):
        background_dct_blocks_h = background.shape[0] // self.block_size  # 高度
        background_dct_blocks_w = background.shape[1] // self.block_size  # 宽度
        background_dct_blocks = np.zeros(shape=(
            (background_dct_blocks_h, background_dct_blocks_w, self.block_size, self.block_size)
        ))  # 前2个维度用来遍历所有block，后2个维度用来存储每个block的DCT变换的值

        h_data = np.vsplit(background, background_dct_blocks_h)
        for h in range(background_dct_blocks_h):
            block_data = np.hsplit(h_data[h], background_dct_blocks_w)
            for w in range(background_dct_blocks_w):
                a_block = block_data[w]
                background_dct_blocks[h, w, ...] = cv2.dct(a_block.astype(np.float64))
        return background_dct_blocks
```
#### 3)水印嵌入
确保输入的水印图像是经过二值归一化处理的（像素值仅为 0 或 1）。遍历水印图像的每个像素位置（对应到背景图像分块的位置），根据当前水印像素值是0还是1，选择对应的随机向量k1或k2，将水印信息嵌入到对应块的 DCT 系数中。具体是修改每个块的最后一列（特定频率分量）的DCT系数，通过加上与嵌入强度系数alpha、所选随机向量相关的值来实现水印嵌入。
```python
    # 水印嵌入，嵌入位置为每个DCT块的最后一列
    def dct_embed(self, dct_data, watermark):
        temp = watermark.flatten()
        assert temp.max() == 1 and temp.min() == 0, "为方便处理，请保证输入的watermark是被二值归一化的"

        result = dct_data.copy()
        for h in range(watermark.shape[0]):
            for w in range(watermark.shape[1]):
                k = self.k1 if watermark[h, w] == 1 else self.k2
                # 查询块(h,w)并遍历对应块的中频系数（主对角线），进行修改
                for i in range(self.block_size):
                    result[h, w, i, self.block_size - 1] = dct_data[h, w, i, self.block_size - 1] + self.alpha * k[i]
        return result
```
#### 4)逆DCT变换与图像合成
对嵌入水印后的DCT系数矩阵进行逆离散余弦变换（cv2.idct），将频域数据转换回空间域。依次对每个块进行逆变换后，再将这些块按照原来的位置拼接起来，得到嵌入水印后的单通道图像，对于彩色图像则是分别处理每个通道后再合并通道，最终得到嵌入水印后的彩色图像。
```python
    # 逆变换重建
    def idct_embed(self, dct_data):
        row = None
        result = None
        h, w = dct_data.shape[0], dct_data.shape[1]
        for i in range(h):
            for j in range(w):
                block = cv2.idct(dct_data[i, j, ...])
                row = block if j == 0 else np.hstack((row, block))
            result = row if i == 0 else np.vstack((result, row))
        return result.astype(np.uint8)
```
### 2、水印提取
#### 1)图像分块与DCT变换
对嵌入水印后的合成图像，按照与嵌入时相同的块大小，使用dct_blkproc方法进行分块并进行DCT变换，获取各块的DCT系数矩阵，以便从中提取水印信息。

#### 2)水印提取
遍历与原始水印图像尺寸对应的各块位置，提取每个块最后一列（嵌入水印时所使用的频率分量）的DCT系数组成向量p。通过计算向量p与嵌入时使用的两个随机向量k1和k2的相关性（利用corr2函数计算相关系数），根据相关性大小来判断当前块位置对应的水印值是 0 还是 1。相关性更大的一方对应的水印值（1 对应k1，0 对应k2）作为提取出的水印像素值，遍历完所有对应位置后，得到完整的提取水印图像，对于彩色图像的各通道提取结果再进行合并等处理。
```python
    # 水印提取
    def dct_extract(self, synthesis, watermark_size):
        w_h, w_w = watermark_size
        recover_watermark = np.zeros(shape=watermark_size)
        synthesis_dct_blocks = self.dct_blkproc(background=synthesis)
        p = np.zeros(self.block_size)
        for h in range(w_h):
            for w in range(w_w):
                for k in range(self.block_size):
                    p[k] = synthesis_dct_blocks[h, w, k, self.block_size - 1]
                # 添加容错处理
                try:
                    if corr2(p, self.k1) > corr2(p, self.k2):
                        recover_watermark[h, w] = 1
                    else:
                        recover_watermark[h, w] = 0
                except:
                    # 如果计算相关系数出错，默认设为0
                    recover_watermark[h, w] = 0
        return recover_watermark
```
## 三、攻击方法
在本项目中使用了高斯噪声，椒盐噪声及各种滤波方式，展示攻击前后图片及所提取的水印的变化
```python
class Attack():
    def __init__(self):
        pass

    @staticmethod
    def Gaussian(attack_obj, mean=0.0, var=1e-2):
        """高斯噪声"""
        result = skiu.random_noise(attack_obj, mode="gaussian", mean=mean, var=var) * 255
        return result.astype(np.uint8)

    @staticmethod
    def SaltPepper(attack_obj):
        """椒盐噪声"""
        result = skiu.random_noise(attack_obj, mode="s&p") * 255
        return result.astype(np.uint8)

    @staticmethod
    def HighPassFilter(attack_obj, kernel_size=3):
        """使用Sobel算子進行高通濾波,kernel_size=3x3"""
        # 处理彩色图像
        if len(attack_obj.shape) == 3:
            result = np.zeros_like(attack_obj)
            for i in range(3):
                grad_x = cv2.Sobel(attack_obj[:, :, i], cv2.CV_16S, 1, 0, ksize=kernel_size)
                grad_y = cv2.Sobel(attack_obj[:, :, i], cv2.CV_16S, 0, 1, ksize=kernel_size)
                imgx_uint8 = cv2.convertScaleAbs(grad_x)
                imgy_uint8 = cv2.convertScaleAbs(grad_y)
                result[:, :, i] = cv2.addWeighted(imgx_uint8, 0.5, imgy_uint8, 0.5, 0)
            return result
        else:
            grad_x = cv2.Sobel(attack_obj, cv2.CV_16S, 1, 0, ksize=kernel_size)
            grad_y = cv2.Sobel(attack_obj, cv2.CV_16S, 0, 1, ksize=kernel_size)
            imgx_uint8 = cv2.convertScaleAbs(grad_x)
            imgy_uint8 = cv2.convertScaleAbs(grad_y)
            result = cv2.addWeighted(imgx_uint8, 0.5, imgy_uint8, 0.5, 0)
            return result

    @staticmethod
    def MedianFilter(attack_obj, kernel_size=3):
        """中值濾波"""
        # 处理彩色图像
        if len(attack_obj.shape) == 3:
            result = np.zeros_like(attack_obj)
            for i in range(3):
                result[:, :, i] = cv2.medianBlur(attack_obj[:, :, i], ksize=kernel_size)
            return result
        else:
            return cv2.medianBlur(attack_obj, ksize=kernel_size)

    @staticmethod
    def MeanFilter(attack_obj, kernel_size=3):
        """均值滤波"""
        # 处理彩色图像
        if len(attack_obj.shape) == 3:
            result = np.zeros_like(attack_obj)
            for i in range(3):
                result[:, :, i] = cv2.blur(attack_obj[:, :, i], ksize=(kernel_size, kernel_size))
            return result
        else:
            return cv2.blur(attack_obj, ksize=(kernel_size, kernel_size))

    @staticmethod
    def Rotate(attack_obj, angle=45):
        """旋转攻击"""
        # 处理彩色图像
        if len(attack_obj.shape) == 3:
            result = transform.rotate(attack_obj, angle, preserve_range=True)
        else:
            result = transform.rotate(attack_obj, angle, preserve_range=True)
        return result.astype(np.uint8)
```
## 四、实验结果
Figure_1.png Figure_2.png
## 五、参考链接
https://blog.csdn.net/2301_76279010/article/details/144728695?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522ae0560c4e0df592b5d9bfc20b08c12f7%2522%252C%2522scm%2522%253A%252220140713.130102334.pc%255Fall.%2522%257D&request_id=ae0560c4e0df592b5d9bfc20b08c12f7&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~all~first_rank_ecpm_v1~rank_v31_ecpm-2-144728695-null-null.142^v102^pc_search_result_base6&utm_term=%E5%9B%BE%E7%89%87%E6%B0%B4%E5%8D%B0%E5%B5%8C%E5%85%A5%E5%92%8C%E6%8F%90%E5%8F%96python&spm=1018.2226.3001.4187  
https://blog.csdn.net/qq_44009107/article/details/125042422?csdn_share_tail=%7B%22type%22%3A%22blog%22%2C%22rType%22%3A%22article%22%2C%22rId%22%3A%22125042422%22%2C%22source%22%3A%22qq_44009107%22%7D&ctrtid=MCk4U
