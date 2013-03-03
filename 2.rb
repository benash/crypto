require 'fast-aes'

class String
  def ^(rhs)
    self.bytes.zip(rhs.bytes).collect { |x| x[0] ^ x[1] }.pack('c*')
  end

  def add(rhs)
    sum = self.unpack('H*')[0].to_i(16) + rhs
    [("%x" %sum)].pack('H*')
  end
end

def cbc_decrypt(key, cipher)
  k = [key].pack('H*')
  c = [cipher].pack('H*')

  blocks = c.scan(/#{'.' * 16}/)

  aes = FastAES.new(k)

  m = ''

  while blocks.size > 1
    m << (blocks.shift ^ aes.decrypt(blocks.first))
  end

  m[0...-m.bytes.to_a.last]
end

def ctr_decrypt(key, cipher)
  k = [key].pack('H*')
  c = [cipher].pack('H*')

  blocks = c.scan(/#{'.' * 16}/)
  blocks.push c[blocks.join.size..-1]
  iv = blocks.shift

  aes = FastAES.new(k)

  m = ''

  i = 0

  while blocks.size > 0
    m << (blocks.shift ^ aes.encrypt(iv.add(i)))
    i += 1
  end

  m
end

key = '140b41b22a29beb4061bda66b6747e14'

ciphers = %w{
  4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81
  5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253
}

ciphers.each do |c|
  puts cbc_decrypt(key, c)
end

key = '36f18357be4dbd77f050515c73fcf9f2'

ciphers = %w{
  69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329
  770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451
}

ciphers.each do |c|
  puts ctr_decrypt(key, c)
end

