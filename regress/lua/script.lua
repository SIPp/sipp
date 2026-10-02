function greet(name, n)
  sipp.set("greeting", "hello " .. name .. " " .. (tonumber(n) + 1))
  sipp.set("count", tonumber(n) * 2)
  sipp.log("input was " .. sipp.get("input"))
end

function broken()
  sipp.set("nosuchvar", "x")
end
