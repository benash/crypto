$ciphers = %w(
315c4eeaa8b5f8aaf9174145bf43e1784b8fa00dc71d885a804e5ee9fa40b16349c146fb778cdf2d3aff021dfff5b403b510d0d0455468aeb98622b137dae857553ccd8883a7bc37520e06e515d22c954eba5025b8cc57ee59418ce7dc6bc41556bdb36bbca3e8774301fbcaa3b83b220809560987815f65286764703de0f3d524400a19b159610b11ef3e
234c02ecbbfbafa3ed18510abd11fa724fcda2018a1a8342cf064bbde548b12b07df44ba7191d9606ef4081ffde5ad46a5069d9f7f543bedb9c861bf29c7e205132eda9382b0bc2c5c4b45f919cf3a9f1cb74151f6d551f4480c82b2cb24cc5b028aa76eb7b4ab24171ab3cdadb8356f
32510ba9a7b2bba9b8005d43a304b5714cc0bb0c8a34884dd91304b8ad40b62b07df44ba6e9d8a2368e51d04e0e7b207b70b9b8261112bacb6c866a232dfe257527dc29398f5f3251a0d47e503c66e935de81230b59b7afb5f41afa8d661cb
32510ba9aab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064ba8ad5ea06a029056f47a8ad3306ef5021eafe1ac01a81197847a5c68a1b78769a37bc8f4575432c198ccb4ef63590256e305cd3a9544ee4160ead45aef520489e7da7d835402bca670bda8eb775200b8dabbba246b130f040d8ec6447e2c767f3d30ed81ea2e4c1404e1315a1010e7229be6636aaa
3f561ba9adb4b6ebec54424ba317b564418fac0dd35f8c08d31a1fe9e24fe56808c213f17c81d9607cee021dafe1e001b21ade877a5e68bea88d61b93ac5ee0d562e8e9582f5ef375f0a4ae20ed86e935de81230b59b73fb4302cd95d770c65b40aaa065f2a5e33a5a0bb5dcaba43722130f042f8ec85b7c2070
32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd2061bbde24eb76a19d84aba34d8de287be84d07e7e9a30ee714979c7e1123a8bd9822a33ecaf512472e8e8f8db3f9635c1949e640c621854eba0d79eccf52ff111284b4cc61d11902aebc66f2b2e436434eacc0aba938220b084800c2ca4e693522643573b2c4ce35050b0cf774201f0fe52ac9f26d71b6cf61a711cc229f77ace7aa88a2f19983122b11be87a59c355d25f8e4
32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd90f1fa6ea5ba47b01c909ba7696cf606ef40c04afe1ac0aa8148dd066592ded9f8774b529c7ea125d298e8883f5e9305f4b44f915cb2bd05af51373fd9b4af511039fa2d96f83414aaaf261bda2e97b170fb5cce2a53e675c154c0d9681596934777e2275b381ce2e40582afe67650b13e72287ff2270abcf73bb028932836fbdecfecee0a3b894473c1bbeb6b4913a536ce4f9b13f1efff71ea313c8661dd9a4ce
315c4eeaa8b5f8bffd11155ea506b56041c6a00c8a08854dd21a4bbde54ce56801d943ba708b8a3574f40c00fff9e00fa1439fd0654327a3bfc860b92f89ee04132ecb9298f5fd2d5e4b45e40ecc3b9d59e9417df7c95bba410e9aa2ca24c5474da2f276baa3ac325918b2daada43d6712150441c2e04f6565517f317da9d3
271946f9bbb2aeadec111841a81abc300ecaa01bd8069d5cc91005e9fe4aad6e04d513e96d99de2569bc5e50eeeca709b50a8a987f4264edb6896fb537d0a716132ddc938fb0f836480e06ed0fcd6e9759f40462f9cf57f4564186a2c1778f1543efa270bda5e933421cbe88a4a52222190f471e9bd15f652b653b7071aec59a2705081ffe72651d08f822c9ed6d76e48b63ab15d0208573a7eef027
466d06ece998b7a2fb1d464fed2ced7641ddaa3cc31c9941cf110abbf409ed39598005b3399ccfafb61d0315fca0a314be138a9f32503bedac8067f03adbf3575c3b8edc9ba7f537530541ab0f9f3cd04ff50d66f1d559ba520e89a2cb2a83
)

target = '32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904'

# Trim all ciphers to be no longer than the target, since we don't need that
# data to decrypt target
$ciphers.collect! { |c| c[0, target.length] }

UNKNOWN = '^'

texts = Array.new($ciphers.size) { UNKNOWN * target.length }

# Split into array of hex characters
$ciphers.collect! { |c| c.scan(/../) }

def xor(a, b)
  (0...[a.length, b.length].min).collect do |i|
    a[i].to_i(16) ^ b[i].to_i(16)
  end
end

def space_indices(a, b, c)

  xab = xor(a, b)
  xac = xor(a, c)
  xbc = xor(b, c)

  spaces = xab.each_index.select do |i|
    xab[i] >= 0x40 && xac[i] >= 0x40 && xbc[i] < 0x40 && xbc[i] != 0
  end

end


def get_non_alpha(i)
  h = {}
  h.default = 0

  $ciphers.each_index do |j|

    if j == i
      next
    end

    (j+1...$ciphers.length).each do |k|
      if k == i
        next
      end

      space_indices($ciphers[i], $ciphers[j], $ciphers[k]).each { |l| h[l] += 1 }
    end
  end

  h.keys.sort
end

$ciphers.each_index do |i|
  $ciphers.each_index do |j|
    if i == j
      next
    end
    puts "#{i} #{j} " + xor($ciphers[i], $ciphers[j]).collect { |x| "%x" %x }.join(' ')
  end
end

def try_val(cipher, index, val)
  key = $ciphers[cipher][index].to_i(16) ^ val.ord

  puts "Position #{index}:"
  puts "%x" %key

  $ciphers.each_index do |i|
    puts ($ciphers[i][index].to_i(16) ^ key).chr
  end

  return
end

try_val(0, 3, ' ')

first = 41
last = 46

key = []

(first..last).each do |i|
  next_part = 0
  $ciphers.each_index do |c|
    high_count = 0

    $ciphers.each_index do |test|

      val = $ciphers[c][i].to_i(16) ^ $ciphers[test][i].to_i(16)
      if val >= 0x40
        high_count += 1
      end
    end

    if high_count >= 5
      next_part = $ciphers[c][i].to_i(16) ^ ' '.ord
      break
    end
  end

  key.push next_part
end

puts key.collect { |x| "%x" %x }.join("\t")

$ciphers.each_index do |c|
  out = []
  (0...key.length).each do |i|
    if key[i] == 0
      out.push UNKNOWN
    else
      out.push ($ciphers[c][first+i].to_i(16) ^ key[i]).chr
    end
  end
  puts out.join("\t")
end

target = '32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904'

key = %w(66 39 6e 89 c9 db d8 cc 98 74 35 2a cd 63 95 10 2e af ce 78 aa 7f ed 28 a0 7f 6b c9 8d 29 c5 b 69 b0 33 9a 19 f8 aa 40 1a 9c 6d 70 8f 80 c0 66 c7 63 fe f0 12 31 48 cd d8 e8 2 d0 5b a9 87 77 33 5d ae fc ec d5 9c 43 3a 6b 26 8b 60 bf 4e f0 3c 9a 61)

key = key.collect { |x| x.to_i(16) }
target = target.scan(/../).collect { |x| x.to_i(16) }

text = []
key.each_index { |i| text.push key[i] ^ target[i] }

puts text.collect { |x| x.chr }.join
