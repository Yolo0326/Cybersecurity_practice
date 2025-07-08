import cv2
import numpy as np
import matplotlib.pyplot as plt
import skimage.util as skiu
from skimage import transform, metrics


class DCT_Embed(object):
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
        """使用Sobel算子進行高通滤波,kernel_size=3x3"""
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
        """中值滤波"""
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

def mean2(x):
    y = np.sum(x) / np.size(x)
    return y


# 相关性判断 - 添加容错处理
def corr2(a, b):
    a = a - mean2(a)
    b = b - mean2(b)

    # 避免除以零的错误
    denom = np.sqrt((a * a).sum() * (b * b).sum())
    if denom == 0:
        return 0  # 如果分母为零，返回0

    r = (a * b).sum() / denom
    return r


if __name__ == '__main__':

    alpha = 10
    blocksize = 8

    watermark = cv2.imread(r"watermark.bmp")
    watermark = cv2.cvtColor(watermark, cv2.COLOR_BGR2RGB)

    watermark_bin = np.where(watermark < np.mean(watermark, axis=(0, 1)), 0, 1)

    background = cv2.imread(r"image.bmp")
    background = cv2.cvtColor(background, cv2.COLOR_BGR2RGB)
    background_backup = background.copy()

    # 如果图像尺寸不是block_size的倍数，调整尺寸
    h, w = background.shape[:2]
    if h % blocksize != 0:
        h = h - (h % blocksize)
    if w % blocksize != 0:
        w = w - (w % blocksize)
    background = background[:h, :w, :]

    channels = cv2.split(background)
    embed_synthesis = []
    extract_watermarks = []
    dct_embs = []  # 保存每个通道的DCT_Embed对象
    for i in range(3):
        dct_emb = DCT_Embed(background=channels[i], watermark=watermark_bin[..., i], block_size=blocksize, alpha=alpha)
        background_dct_blocks = dct_emb.dct_blkproc(background=channels[i])
        embed_watermark_blocks = dct_emb.dct_embed(dct_data=background_dct_blocks, watermark=watermark_bin[..., i])
        synthesis = dct_emb.idct_embed(dct_data=embed_watermark_blocks)
        embed_synthesis.append(synthesis)
        extract_watermarks.append(
            dct_emb.dct_extract(synthesis=synthesis, watermark_size=watermark_bin[..., i].shape) * 255)
        dct_embs.append(dct_emb)  # 保存对象用于后续攻击

    rbg_synthesis = cv2.merge(embed_synthesis)
    extract_watermark = cv2.merge([ew.astype(np.uint8) for ew in extract_watermarks])

    # 展示原始图像、水印、合成图像和提取的水印
    plt.figure(figsize=(12, 8))
    images = [background_backup, watermark, rbg_synthesis, extract_watermark]
    titles = ["Original Image", "Watermark", "Watermarked Image", "Extracted Watermark"]
    for i in range(4):
        plt.subplot(2, 2, i + 1)
        plt.imshow(images[i])
        plt.title(titles[i])
        plt.axis("off")
    plt.tight_layout()
    plt.show()

    # ================== 添加攻击部分 ==================
    # 定义攻击列表
    attacks = [
        ("Gaussian Noise", lambda img: Attack.Gaussian(img, var=0.01)),
        ("Salt & Pepper", Attack.SaltPepper),
        ("High Pass Filter", lambda img: Attack.HighPassFilter(img)),
        ("Median Filter", lambda img: Attack.MedianFilter(img, kernel_size=5)),
        ("Mean Filter", lambda img: Attack.MeanFilter(img, kernel_size=5)),
        ("Rotation", lambda img: Attack.Rotate(img, angle=30))
    ]

    # 创建两行布局
    plt.figure(figsize=(18, 8))

    # 第一行：攻击后的含水印图像
    # 添加原始含水印图像作为第一个图像
    plt.subplot(2, len(attacks) + 1, 1)
    plt.imshow(rbg_synthesis)
    plt.title("Watermarked Image\n(No Attack)")
    plt.axis('off')

    # 第二行：提取的水印
    # 添加原始提取的水印作为第一个图像
    plt.subplot(2, len(attacks) + 1, len(attacks) + 2)
    plt.imshow(extract_watermark)
    plt.title("Extracted Watermark\n(No Attack)")
    plt.axis('off')

    # 对每种攻击进行处理
    for idx, (attack_name, attack_func) in enumerate(attacks):
        # 应用攻击
        attacked_img = attack_func(rbg_synthesis.copy())

        # 分离通道并提取水印
        attacked_channels = cv2.split(attacked_img)
        attacked_extracts = []
        for i in range(3):
            # 使用之前保存的DCT_Embed对象提取水印
            try:
                extract = dct_embs[i].dct_extract(
                    synthesis=attacked_channels[i],
                    watermark_size=watermark_bin[..., i].shape
                ) * 255
                attacked_extracts.append(extract)
            except:
                # 如果提取失败，创建一个空水印
                attacked_extracts.append(np.zeros(watermark_bin[..., i].shape))

        attacked_watermark = cv2.merge([ew.astype(np.uint8) for ew in attacked_extracts])

        # 计算PSNR
        try:
            psnr = metrics.peak_signal_noise_ratio(rbg_synthesis, attacked_img, data_range=255)
        except:
            psnr = float('inf')  # 如果计算失败，设为无穷大

        # 第一行：攻击后的含水印图像
        plt.subplot(2, len(attacks) + 1, idx + 2)
        plt.imshow(attacked_img)
        plt.title(f"{attack_name}\nPSNR: {psnr:.2f}dB")
        plt.axis('off')

        # 第二行：攻击后提取的水印
        plt.subplot(2, len(attacks) + 1, len(attacks) + 3 + idx)
        plt.imshow(attacked_watermark)
        plt.title(f"Extracted after {attack_name}")
        plt.axis('off')

    plt.tight_layout()
    plt.show()