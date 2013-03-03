require 'digest'

block_size = 1024

s = open('intro.mp4', 'rb') { |f| f.read };

blocks = []
until s.empty?
  blocks << s.slice!(0, block_size)
end

digest = ''

until blocks.empty?
  sha256 = Digest::SHA256.new
  sha256.update blocks.pop
  sha256.update digest
  digest = sha256.digest
end

puts digest.unpack('H*')

