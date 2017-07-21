package body Foo is

  Initial_Value : constant := 100.0;

  Value : My_Float := Initial_Value; 

  procedure Increase is
  begin
    Value := Value + 5.0;
  end Increase;
  
  procedure Reset is
  begin
    Value := Initial_Value;
  end Reset;

end Foo;
